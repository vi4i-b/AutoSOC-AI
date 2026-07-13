"""Main dashboard window: scanning, firewall control, alerting, AI copilot.

Widget construction lives in :class:`DashboardLayoutMixin`
(:mod:`autosoc.ui.dashboard_layout`); this class owns state and behavior.
All OS work goes through :mod:`autosoc.system` so the window itself is
platform-independent.
"""

import json
import os
import queue
import socket
import threading
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from autosoc.ai.expert import AISecurityExpert
from autosoc.ai.nvidia import NvidiaSecurityAI
from autosoc.analyzer import RiskAnalyzer
from autosoc.auth import get_user_telegram, update_user_telegram
from autosoc.canary import PortCanary
from autosoc.database import SOCDatabase
from autosoc.env import load_env_file
from autosoc.guard import NetworkGuard
from autosoc.logging_setup import get_logger
from autosoc.phishing import PhishingAnalyzer
from autosoc.ports import DEFAULT_RISKY_PORTS, TRACKED_PORTS
from autosoc.scanner import NetworkScanner, count_open_ports, summarize_single_port_state
from autosoc.system import hardening
from autosoc.system.firewall import get_firewall
from autosoc.system.log_monitor import create_log_listener
from autosoc.system.netinfo import target_appears_remote
from autosoc.system.privileges import is_admin, privilege_hint
from autosoc.system.response import ResponseController
from autosoc.telegram.client import TelegramBotClient, escape_markdown
from autosoc.telegram.listener import TelegramUpdateListener, extract_command, extract_contact
from autosoc.ui import theme
from autosoc.ui.dashboard_layout import DashboardLayoutMixin
from autosoc.ui.theme import apply_window_icon
from autosoc.validators import is_safe_scan_target, looks_like_chat_id

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

log = get_logger("ui.dashboard")

TELEGRAM_BOT_URL_DEFAULT = "https://t.me/AutoSOC_Baku_Bot"


class AutoSOCApp(DashboardLayoutMixin, ctk.CTk):
    FAQ_ITEMS = [
        "445 portu niyə təhlükəlidir?",
        "Son scan nəticəsini izah et",
        "RDP açıqdırsa nə etməliyəm?",
        "Fişinqdən necə qorunum?",
        "Şübhəli portları bağla",
        "Explain the current risk posture",
    ]

    def __init__(self, current_user=None):
        super().__init__()
        load_env_file()
        apply_window_icon(self)

        self.db = SOCDatabase()
        self.current_user = current_user or {}
        self.firewall = get_firewall()
        self.port_definitions = dict(TRACKED_PORTS)
        self.switches = {}

        self._init_telegram_state()

        self.ai_expert = AISecurityExpert()
        self.nvidia_ai = NvidiaSecurityAI()
        self._load_nvidia_credentials()
        self.phishing_analyzer = PhishingAnalyzer(ai_client=self.nvidia_ai)
        self.last_phishing_report = None
        self.analyzer = RiskAnalyzer()
        self.guard = NetworkGuard(self.on_threat_detected)
        self.port_canary = PortCanary(self.on_canary_trip)
        self.response = ResponseController(self.db, local_firewall=self.firewall)
        self.soc_console = None
        self.collector = None
        self.syslog = None
        self.last_scan_data = []
        self.scan_summary = ""
        self.ai_loader_job = None
        self.ai_loader_step = 0
        self.chat_history = []
        self.incident_count = 0
        self.previous_scan_snapshot = self._load_exposure_baseline()
        self.latest_new_exposures = []
        self.ui_queue = queue.Queue()
        self.log_listener = None
        self.log_listener_warning_shown = False
        self.default_scan_target = self._detect_default_target()

        self.title("AutoSOC: Cyber Shield v3.0")
        self.geometry("1440x960")
        self.minsize(1280, 840)
        self.configure(fg_color=theme.BG_DEEP)

        # Fixed-width sidebar, elastic main panel.
        self.grid_columnconfigure(0, minsize=390, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_main_panel()
        self._build_sidebar()
        self._build_new_tab_panel()
        self._show_page("dashboard")
        self._render_intro_message()
        self._warn_if_not_admin()
        self._refresh_dashboard_metrics()
        self._refresh_prevention_status()
        self._check_telegram_status()
        self.after(120, self._drain_ui_queue)
        self.start_log_listener()
        self.telegram_listener.start()

        # Initial scan so the dashboard shows live port state right away.
        self.after(400, self.start_scan_thread)

    def _init_telegram_state(self):
        saved_chat_id = (self.db.get_setting("telegram_chat_id", "") or "").strip()
        latest_tg_user = self.db.get_latest_telegram_user()
        username = self.current_user.get("username", "")
        user_tg = get_user_telegram(username) if username else None

        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = (
            (user_tg or {}).get("telegram_chat_id", "").strip()
            or self.current_user.get("telegram_chat_id", "").strip()
            or saved_chat_id
            or os.getenv("TELEGRAM_CHAT_ID", "").strip()
        )
        if not self.chat_id and latest_tg_user:
            self.chat_id = str(latest_tg_user["telegram_chat_id"])

        self.telegram_bot_url = (os.getenv("TELEGRAM_BOT_URL") or TELEGRAM_BOT_URL_DEFAULT).strip()
        self.telegram_client = TelegramBotClient(self.bot_token)
        self.telegram_listener = TelegramUpdateListener(
            self.telegram_client,
            on_update=self._handle_telegram_update,
            on_state=self._on_telegram_listener_state,
        )
        self.telegram_bot_online = False
        self.bot_identity = None

    def _detect_default_target(self):
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"

    def _warn_if_not_admin(self):
        if is_admin():
            return
        self._append_result(
            f"[ADMIN] AutoSOC is running without elevated privileges. {privilege_hint()}\n",
            "info",
            index="0.0",
        )

    # ── thread-safe UI plumbing ──────────────────────────────────────

    def _ui(self, callback):
        if threading.current_thread() is threading.main_thread():
            try:
                callback()
            except tk.TclError:
                pass
            return
        self.ui_queue.put(callback)

    def _drain_ui_queue(self):
        try:
            while True:
                callback = self.ui_queue.get_nowait()
                try:
                    callback()
                except tk.TclError:
                    pass
        except queue.Empty:
            pass

        try:
            if self.winfo_exists():
                self.after(120, self._drain_ui_queue)
        except tk.TclError:
            pass

    def _append_result(self, text, tag=None, index="end"):
        def update():
            if tag:
                self.result_box.insert(index, text, tag)
            else:
                self.result_box.insert(index, text)
            self.result_box.see("end")

        self._ui(update)

    def _set_scan_summary_text(self, text):
        def update():
            self.assistant_summary.delete("0.0", "end")
            self.assistant_summary.insert("end", text)

        self._ui(update)

    def _set_status(self, text, color):
        self._ui(lambda: self.status_label.configure(text=text, text_color=color))

    # ── intro / metrics ──────────────────────────────────────────────

    def _render_intro_message(self):
        intro = (
            "AutoSOC hazırdır.\n\n"
            "Mən Azərbaycan dilini dəstəkləyirəm və son scan kontekstini yadda saxlayıram.\n"
            "Qısa follow-up sualları da başa düşürəm: məsələn, 'bunu bağla', 'niyə təhlükəlidir?', 'nə edək?'."
        )
        self.assistant_output.delete("0.0", "end")
        self.assistant_output.insert("end", intro)
        self.assistant_summary.delete("0.0", "end")
        self.assistant_summary.insert("end", "No scan data yet. Run a scan and I will generate a risk-aware brief.")
        self.result_box.insert("end", "[SYSTEM] Dashboard initialized.\n", "muted")

    def _append_chat_message(self, sender, text):
        self.chat_history.append((sender, text))
        self.chat_history = self.chat_history[-14:]
        self.assistant_output.delete("0.0", "end")
        for sender_name, content in self.chat_history:
            prefix = "You" if sender_name == "You" else "AutoSOC"
            self.assistant_output.insert("end", f"{prefix}\n{content}\n\n")
        self.assistant_output.see("end")

    def _build_nvidia_chat_history(self):
        history = []
        for sender, text in self.chat_history[-10:]:
            role = "user" if sender == "You" else "assistant"
            history.append({"role": role, "content": text})
        return history

    def _refresh_dashboard_metrics(self):
        total_devices = len(self.last_scan_data)
        open_ports = count_open_ports(self.last_scan_data)
        findings = self._collect_risks(self.last_scan_data)
        risk_score = self.analyzer.calculate_risk_score(findings)

        self.metric_total_devices.configure(text=str(total_devices))
        self.metric_open_ports.configure(text=str(open_ports))
        self.metric_risk.configure(text=f"{risk_score}%")
        self.metric_incidents.configure(text=str(self.incident_count))

        if self.telegram_bot_online and self.chat_id and self.telegram_listener.healthy:
            self.metric_tg.configure(text="Ready", text_color="#6de0a8")
        elif self.telegram_bot_online and self.chat_id:
            self.metric_tg.configure(text="Bot Online", text_color=theme.STATUS_GOOD)
        elif self.telegram_bot_online:
            self.metric_tg.configure(text="No Chat ID", text_color=theme.STATUS_WARN)
        else:
            self.metric_tg.configure(text="Offline", text_color=theme.STATUS_DANGER)

    def _check_telegram_status(self):
        if not self.telegram_client.enabled:
            self.telegram_bot_online = False
            self.tg_status.configure(
                text="Telegram bot token tapılmadı. .env faylında TELEGRAM_BOT_TOKEN əlavə edin.",
                text_color=theme.STATUS_ERROR,
            )
            self._refresh_dashboard_metrics()
            return

        ok, data = self.telegram_client.get_me()
        if ok:
            self.telegram_bot_online = True
            username = data.get("result", {}).get("username", "bot")
            self.bot_identity = username
            text = f"Bot online: @{username}"
            if self.chat_id:
                text += f"\nActive chat_id: {self.chat_id}"
            self.tg_status.configure(text=text, text_color=theme.STATUS_GOOD)
        else:
            self.telegram_bot_online = False
            self.tg_status.configure(
                text=f"Telegram xətası: {data.get('description', 'unknown error')}",
                text_color=theme.STATUS_ERROR,
            )
        self._refresh_dashboard_metrics()

    # ── risk / exposure helpers ──────────────────────────────────────

    def _collect_risks(self, data):
        risks = []
        for device in data or []:
            risks.extend(self.analyzer.analyze(device.get("ports", [])))
        return risks

    def _extract_open_port_snapshot(self, data):
        snapshot = set()
        for device in data or []:
            ip = device.get("ip", "unknown")
            for port_info in device.get("ports", []):
                snapshot.add((ip, int(port_info["port"])))
        return snapshot

    def _load_exposure_baseline(self):
        raw_value = self.db.get_setting("exposure_baseline", "")
        if not raw_value:
            return None

        try:
            items = json.loads(raw_value)
        except (TypeError, json.JSONDecodeError):
            return None

        snapshot = set()
        for item in items or []:
            try:
                snapshot.add((str(item["ip"]), int(item["port"])))
            except (KeyError, TypeError, ValueError):
                continue
        return snapshot

    def _persist_exposure_baseline(self):
        if self.previous_scan_snapshot is None:
            return

        payload = [
            {"ip": ip, "port": port}
            for ip, port in sorted(self.previous_scan_snapshot)
        ]
        self.db.set_setting("exposure_baseline", json.dumps(payload))

    def _update_exposure_baseline(self, data):
        current_snapshot = self._extract_open_port_snapshot(data)
        if self.previous_scan_snapshot is None:
            self.previous_scan_snapshot = current_snapshot
            self._persist_exposure_baseline()
            self.latest_new_exposures = []
            return []

        new_entries = current_snapshot - self.previous_scan_snapshot
        self.previous_scan_snapshot = current_snapshot
        self._persist_exposure_baseline()
        self.latest_new_exposures = [
            {"ip": ip, "port": port, "service": self.port_definitions.get(port, "Unknown")}
            for ip, port in sorted(new_entries)
        ]
        return self.latest_new_exposures

    def _refresh_prevention_status(self):
        canary_state = self.port_canary.status()
        if canary_state["running"] and canary_state["bound_ports"]:
            canary_text = "Port Canary active on " + ", ".join(str(port) for port in canary_state["bound_ports"])
            self.btn_canary.configure(
                text="Port Canary: On",
                fg_color=theme.ACCENT_GREEN_DARK,
                hover_color=theme.ACCENT_GREEN_DARK_HOVER,
            )
        else:
            canary_text = "Canary idle. Risky-port hardening is ready."
            self.btn_canary.configure(
                text="Port Canary: Off",
                fg_color=theme.BTN_NEUTRAL,
                hover_color=theme.BTN_NEUTRAL_HOVER,
            )

        extras = []
        if self.latest_new_exposures:
            extras.append(f"New exposure drift: {len(self.latest_new_exposures)} newly opened service(s).")
        if self.incident_count:
            extras.append(f"Incidents captured: {self.incident_count}.")
        failed_ports = canary_state.get("failed_ports", {})
        if failed_ports:
            extras.append("Unavailable canary ports: " + ", ".join(str(port) for port in failed_ports))

        status_text = canary_text if not extras else canary_text + "\n" + "\n".join(extras)
        self.prevention_status.configure(text=status_text)

    # ── port switches ────────────────────────────────────────────────

    def enable_all_ports(self):
        for port, switch in self.switches.items():
            if not switch.get():
                switch.select()
                self.toggle_port(port, switch, verify=False)
        self.result_box.insert("0.0", "[FIREWALL] All tracked ports allowed\n", "success")
        self._refresh_dashboard_metrics()

    def disable_all_ports(self):
        for port, switch in self.switches.items():
            if switch.get():
                switch.deselect()
                self.toggle_port(port, switch, verify=False)
        self.result_box.insert("0.0", "[FIREWALL] All tracked ports blocked\n", "danger")
        self._refresh_dashboard_metrics()

    def toggle_port(self, port, switch_obj, verify=True):
        is_open = bool(switch_obj.get())
        service = self.port_definitions.get(port, "Unknown")

        if self.firewall is None:
            switch_obj.deselect() if is_open else switch_obj.select()
            self.result_box.insert("0.0", "[FIREWALL] No supported firewall backend on this platform.\n", "danger")
            return

        if not is_admin():
            self.result_box.insert(
                "0.0",
                f"[ADMIN] Elevated privileges are missing. {privilege_hint()}\n",
                "danger",
            )

        success, rule_name, firewall_message = self.firewall.set_port_blocked(port, blocked=not is_open)
        if not success:
            # Roll the switch back so the UI reflects reality.
            if is_open:
                switch_obj.deselect()
            else:
                switch_obj.select()

        state_text = "ALLOWED" if is_open else "BLOCKED"
        result_state = state_text if success else f"{state_text} (with error)"
        self.result_box.insert(
            "0.0",
            f"[FIREWALL] Port {port} ({service}) {result_state}\n{firewall_message}\n",
            "success" if success and is_open else "danger" if not is_open else "info",
        )
        self.db.add_security_event(
            "firewall_port_change",
            "Low" if is_open else "Medium",
            "local_firewall",
            f"Port {port} ({service}) -> {state_text}. Rule: {rule_name or 'n/a'}. Result: {firewall_message}",
        )

        if success and is_open:
            open_message = hardening.attempt_service_open(port, service)
            if open_message:
                self.result_box.insert("0.0", open_message, "info")

        if success and verify:
            target = self.ip_entry.get().strip()
            if target_appears_remote(target):
                self.result_box.insert(
                    "0.0",
                    (
                        f"[VERIFY] Port Control changed this host only. "
                        f"Target {target} appears remote, so its port {port} will not close from this app.\n"
                    ),
                    "danger",
                )
            if target and is_safe_scan_target(target):
                threading.Thread(
                    target=self._verify_port_state_after_firewall_change,
                    args=(target, port, service, is_open),
                    daemon=True,
                ).start()
        self._refresh_dashboard_metrics()

    def _verify_port_state_after_firewall_change(self, target, port, service, allowed):
        self._append_result(f"[VERIFY] Raw scan check for {target}:{port} started\n", "muted", "0.0")
        scanner = NetworkScanner()
        data = scanner.scan_network(target, ports=[port])
        state = summarize_single_port_state(data, port)

        if allowed:
            message = f"[VERIFY] Port {port} ({service}) raw scan state after allow: {state.upper()}\n"
            tag = "info" if state == "open" else "muted"
        elif state == "open":
            message = (
                f"[VERIFY] Port {port} ({service}) still scans OPEN. "
                "The listener is still active, or this local scan is not proving inbound firewall blocking.\n"
            )
            tag = "danger"
            if not target_appears_remote(target):
                hardening_message = hardening.attempt_service_close(port, service)
                if hardening_message:
                    message += hardening_message
                    data_after_hardening = scanner.scan_network(target, ports=[port])
                    hardened_state = summarize_single_port_state(data_after_hardening, port)
                    message += f"[VERIFY] Port {port} ({service}) raw scan after service hardening: {hardened_state.upper()}\n"
                    if hardened_state in {"closed", "filtered"}:
                        tag = "success"
                else:
                    message += "Confirm the firewall result from another machine on the network.\n"
            else:
                message += "Confirm the firewall result from another machine on the network.\n"
        elif state in {"closed", "filtered"}:
            message = f"[VERIFY] Port {port} ({service}) raw scan state after block: {state.upper()}\n"
            tag = "success"
        else:
            message = f"[VERIFY] Port {port} ({service}) raw scan state after block is unclear: {state.upper()}\n"
            tag = "muted"

        self._append_result(message, tag, "0.0")

    def harden_risky_ports(self):
        if self.last_scan_data:
            risky_ports = [item["port"] for item in self._collect_risks(self.last_scan_data)]
        else:
            risky_ports = list(DEFAULT_RISKY_PORTS)

        hardened = []
        for port in sorted(set(risky_ports)):
            switch = self.switches.get(port)
            if switch and switch.get():
                switch.deselect()
                self.toggle_port(port, switch)
                hardened.append(str(port))

        if hardened:
            message = f"[HARDENING] Blocked risky ports: {', '.join(hardened)}\n"
            self.result_box.insert("0.0", message, "danger")
            self.db.add_security_event("hardening_action", "Medium", "local_policy", message.strip())
        else:
            self.result_box.insert("0.0", "[HARDENING] No additional risky ports required blocking\n", "success")

        self._refresh_prevention_status()
        self._refresh_dashboard_metrics()

    # ── canary ───────────────────────────────────────────────────────

    def toggle_port_canary(self):
        if not self.port_canary.is_running:
            status = self.port_canary.start()
            if status["bound_ports"]:
                self.result_box.insert(
                    "0.0",
                    f"[CANARY] Listening on decoy ports: {', '.join(str(port) for port in status['bound_ports'])}\n",
                    "ai",
                )
                self.status_label.configure(text="PORT CANARY ACTIVE", text_color=theme.STATUS_GOOD)
            else:
                self.result_box.insert("0.0", "[CANARY] Failed to bind decoy ports\n", "danger")
        else:
            self.port_canary.stop()
            self.result_box.insert("0.0", "[CANARY] Decoy listeners stopped\n", "muted")
            self.status_label.configure(text="SYSTEM READY", text_color=theme.STATUS_OK)

        self._refresh_prevention_status()
        self._refresh_dashboard_metrics()

    def run_port_canary_self_test(self):
        if not self.port_canary.is_running:
            self.port_canary.start()
        try:
            test_port = self.port_canary.self_test()
            self.result_box.insert(
                "0.0",
                f"[CANARY TEST] Simulated local connection against decoy port {test_port}\n",
                "info",
            )
            self._refresh_prevention_status()
        except Exception as exc:
            self.result_box.insert("0.0", f"[CANARY TEST ERROR] {exc}\n", "danger")

    def on_canary_trip(self, event):
        ip = event["source_ip"]
        port = event["port"]
        source = f"{ip}:{event['source_port']}"
        is_local = event.get("is_local", False)
        severity = "Medium" if is_local else "High"
        details = (
            f"Connection attempt detected on decoy port {port} from {source} at {event['timestamp']}."
            + (" Local self-test or localhost activity." if is_local else " Remote host touched a honeypot port.")
        )

        self.incident_count += 1
        self.db.add_security_event("port_canary_trip", severity, source, details)

        block_result = "logged only"
        if not is_local:
            blocked, rule_name, block_result = self._block_ip(ip, rule_prefix="AutoSOC_Canary_Block")
            if not blocked:
                self.db.add_security_event(
                    "firewall_action_failed",
                    "Medium",
                    source,
                    f"Canary block failed. Rule: {rule_name or 'n/a'}. Result: {block_result}",
                )

        self._append_result(
            f"[CANARY ALERT] {details}\n[CANARY ACTION] {block_result}\n",
            "danger" if not is_local else "info",
        )
        self._set_status("PORT CANARY ALERT", theme.STATUS_ERROR if not is_local else theme.STATUS_WARN)
        self._ui(self._refresh_dashboard_metrics)
        self._ui(self._refresh_prevention_status)

        if self.chat_id:
            alert = (
                f"🚨 *AutoSOC Port Canary*\n\n"
                f"Source: `{escape_markdown(source)}`\n"
                f"Decoy port: `{port}`\n"
                f"Severity: *{severity}*\n"
                f"Action: *{'logged only (local test)' if is_local else 'firewall block attempted'}*"
            )
            threading.Thread(target=self.send_telegram_alert, args=(alert,), daemon=True).start()

    # ── guard / firewall reactions ───────────────────────────────────

    def _block_ip(self, ip, rule_prefix="AutoSOC_Guard_Block"):
        """Block across every channel (feed + appliance + local firewall).

        Returns (ok, rule_name, message) to match the existing call sites.
        """
        ok, summary, _results = self.response.block_ip(
            ip, reason=rule_prefix, actor=self.current_user.get("username", "autosoc"),
        )
        return ok, "", summary

    def update_threshold(self, value):
        self.guard.set_threshold(value)
        self.slider_label.configure(text=f"DDoS Sensitivity: {int(value)}")

    def toggle_guard(self):
        if not self.guard.is_monitoring:
            if not self.guard.start_monitoring():
                self.result_box.insert("0.0", f"[GUARD] {self.guard.unavailable_reason}\n", "danger")
                return
            self.btn_guard.configure(
                text="Guard: Active",
                fg_color=theme.ACCENT_GREEN_DARK,
                hover_color=theme.ACCENT_GREEN_DARK_HOVER,
            )
            self.status_label.configure(text="GUARD ACTIVE", text_color=theme.STATUS_OK)
        else:
            self.guard.stop()
            self.btn_guard.configure(
                text="Guard: Off",
                fg_color=theme.BTN_NEUTRAL,
                hover_color=theme.BTN_NEUTRAL_HOVER,
            )
            self.status_label.configure(text="SYSTEM READY", text_color=theme.STATUS_OK)

    def on_threat_detected(self, ip, reason):
        self.incident_count += 1
        blocked, rule_name, block_message = self._block_ip(ip)
        action_text = "Blocked automatically." if blocked else "Automatic block failed. Manual action required."
        self.db.add_security_event(
            "traffic_spike",
            "High",
            ip,
            f"{reason}. Firewall rule: {rule_name or 'n/a'}. Result: {block_message}",
        )
        alert_ui = f"\n[THREAT] Suspicious activity from {ip}\n[ACTION] {action_text}\n"
        if not blocked:
            alert_ui += f"[DETAIL] {block_message}\n"
        self._ui(lambda: self.result_box.insert("0.0", alert_ui, "danger"))
        self._set_status("GUARD BLOCKED THREAT" if blocked else "GUARD ALERT", theme.STATUS_ERROR)
        self._ui(self._refresh_dashboard_metrics)
        self._ui(self._refresh_prevention_status)

        alert_tg = (
            f"🚨 *AutoSOC Threat Detected*\n\n"
            f"IP: `{escape_markdown(ip)}`\n"
            f"Reason: {escape_markdown(reason)}\n"
            f"Action: {'Automatically blocked' if blocked else 'Automatic block failed'}"
        )
        if not blocked:
            alert_tg += f"\nDetails: {escape_markdown(block_message)}"
        threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()

    # ── failed-login monitoring ──────────────────────────────────────

    def start_log_listener(self):
        if self.log_listener:
            return

        self.log_listener = create_log_listener(
            on_detection=self.on_bruteforce_detected,
            on_error=self.on_log_listener_error,
            threshold=5,
            window_seconds=10,
            poll_interval=1.0,
        )

        if self.log_listener and self.log_listener.start():
            return

        if not self.log_listener_warning_shown:
            self.log_listener_warning_shown = True
            self._append_result(
                "[WARN] Failed-login monitoring unavailable on this system. "
                "Windows: install pywin32 and run as Administrator. "
                "Linux: run as root or join the 'adm' group.\n",
                "info",
                index="0.0",
            )

    def on_log_listener_error(self, message):
        if self.log_listener_warning_shown:
            return
        self.log_listener_warning_shown = True
        self._append_result(f"[WARN] {message}\n", "info", index="0.0")

    def on_bruteforce_detected(self, detection):
        source_ip = detection.get("ip", "unknown")
        attempt_count = detection.get("attempt_count", 0)
        window_seconds = detection.get("window_seconds", 10)
        service_name = detection.get("service", "Logon")
        details = (
            f"Detected {attempt_count} failed {service_name} attempts "
            f"from {source_ip} within {window_seconds} seconds."
        )

        self.incident_count += 1
        self.db.add_security_event("login_bruteforce", "Critical", source_ip, details)
        self._append_result(f"[CRITICAL] {service_name} brute-force detected from {source_ip}!\n", "danger", index="0.0")
        self._set_status("BRUTE-FORCE DETECTED", theme.STATUS_DANGER)
        self._ui(self._refresh_dashboard_metrics)

    # ── telegram ─────────────────────────────────────────────────────

    def save_telegram_id(self):
        new_id = self.tg_entry.get().strip()
        if not new_id:
            self.tg_status.configure(text="Chat ID is empty.", text_color=theme.STATUS_ERROR)
            return
        if not looks_like_chat_id(new_id):
            self.tg_status.configure(text="Chat ID format looks invalid.", text_color=theme.STATUS_ERROR)
            return

        self.chat_id = new_id
        if self.current_user.get("username"):
            if not update_user_telegram(self.current_user["username"], self.chat_id):
                self.tg_status.configure(
                    text="This Telegram Chat ID is already linked to another account.",
                    text_color=theme.STATUS_ERROR,
                )
                return
            self.current_user["telegram_chat_id"] = self.chat_id
        self.db.set_setting("telegram_chat_id", self.chat_id)
        self.db.add_audit_event(
            "telegram_binding_requested",
            self.current_user.get("username", "local_operator"),
            f"Telegram Chat ID set to {self.chat_id}.",
        )
        self.tg_status.configure(text="Testing Telegram connection...", text_color=theme.STATUS_WARN)
        self._refresh_dashboard_metrics()
        threading.Thread(target=self._send_test_message, daemon=True).start()

    def _send_test_message(self):
        ok, data = self.telegram_client.send_message(
            self.chat_id,
            "✅ *AutoSOC connected*\nTelegram notifications are now linked to this chat.",
        )
        if ok:
            self.db.add_audit_event(
                "telegram_binding_verified",
                self.current_user.get("username", "local_operator"),
                f"Telegram notifications verified for {self.chat_id}.",
            )
            self._ui(lambda: self.tg_status.configure(
                text=f"Chat ID verified successfully.\nActive chat_id: {self.chat_id}",
                text_color=theme.STATUS_GOOD,
            ))
            self._ui(self._refresh_dashboard_metrics)
        else:
            self.db.add_audit_event(
                "telegram_binding_failed",
                self.current_user.get("username", "local_operator"),
                f"Telegram send failed for {self.chat_id}: {data.get('description', 'unknown error')}",
            )
            self._ui(lambda: self.tg_status.configure(
                text=f"Telegram send failed: {data.get('description', 'unknown error')}",
                text_color=theme.STATUS_ERROR,
            ))

    def send_telegram_alert(self, message_text):
        if not self.chat_id:
            return
        final_message = message_text
        if self.scan_summary and "*AI advice:*" not in final_message:
            final_message = f"{message_text}\n\n*AI advice:*\n{escape_markdown(self.scan_summary)}"
        ok, data = self.telegram_client.send_message(self.chat_id, final_message)
        if not ok:
            self._ui(lambda: self.result_box.insert(
                "0.0",
                f"[TELEGRAM ERROR] {data.get('description', 'unknown error')}\n",
                "danger",
            ))

    def restart_telegram_listener(self):
        self.telegram_listener.stop()
        self.telegram_listener = TelegramUpdateListener(
            self.telegram_client,
            on_update=self._handle_telegram_update,
            on_state=self._on_telegram_listener_state,
        )
        self.after(1200, self.telegram_listener.start)
        self.tg_status.configure(text="Telegram listener restarting...", text_color=theme.STATUS_WARN)
        self._refresh_dashboard_metrics()

    def _on_telegram_listener_state(self, healthy, description):
        if not healthy:
            self._ui(lambda: self.tg_status.configure(
                text=f"Telegram listener error: {description}",
                text_color=theme.STATUS_ERROR,
            ))
        self._ui(self._refresh_dashboard_metrics)

    def _handle_telegram_update(self, update):
        contact = extract_contact(update)
        if not contact:
            return
        chat_id, user_id, text, from_user = contact

        if user_id is not None and chat_id is not None:
            self.db.save_latest_telegram_user(
                telegram_user_id=str(user_id),
                telegram_chat_id=str(chat_id),
                username=from_user.get("username", ""),
                first_name=from_user.get("first_name", ""),
                last_name=from_user.get("last_name", ""),
                raw_payload=json.dumps(update, ensure_ascii=False),
            )
            self.chat_id = str(chat_id)
            if self.current_user.get("username"):
                if update_user_telegram(self.current_user["username"], self.chat_id, str(user_id)):
                    self.current_user["telegram_chat_id"] = self.chat_id
                    self.current_user["telegram_user_id"] = str(user_id)
            self.db.set_setting("telegram_chat_id", self.chat_id)
            self._ui(self._sync_telegram_chat_id_ui)
            self._ui(self._refresh_dashboard_metrics)

        if not text:
            return

        command = extract_command(text)
        normalized = text.lower()
        if command in ("start", "id"):
            response = (
                "AutoSOC is connected.\n"
                f"Telegram User ID: {user_id}\n"
                f"Telegram Chat ID: {chat_id}\n\n"
                "Use the Telegram Chat ID during registration in the app.\n"
                "After login, scan alerts and port information will be sent to this chat."
            )
            self.telegram_client.send_message(chat_id, response, parse_mode=None)
        elif command == "help":
            help_text = (
                "Available commands:\n"
                "/start - connect this chat\n"
                "/id - show your current IDs\n"
                "/help - show this help"
            )
            self.telegram_client.send_message(chat_id, help_text, parse_mode=None)
        elif normalized in ("start", "id", "hello", "hi"):
            self.telegram_client.send_message(
                chat_id,
                (
                    "Chat linked successfully.\n"
                    f"Telegram Chat ID: {chat_id}\n"
                    "Use this Chat ID during registration in the app.\n"
                    "You can use /start, /id or /help at any time."
                ),
                parse_mode=None,
            )

    def _sync_telegram_chat_id_ui(self):
        self.tg_entry.delete(0, "end")
        self.tg_entry.insert(0, self.chat_id)
        self.tg_status.configure(
            text=f"Chat ID captured from Telegram.\nActive chat_id: {self.chat_id}",
            text_color=theme.STATUS_GOOD,
        )

    # ── scanning ─────────────────────────────────────────────────────

    def start_scan_thread(self):
        target = self.ip_entry.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Please enter an IP address or hostname.")
            return
        if not is_safe_scan_target(target):
            messagebox.showwarning(
                "Invalid Target",
                "Enter a single IP address, CIDR range, hostname, or localhost without spaces or special shell characters.",
            )
            return
        self.last_scan_data = []
        self.btn_scan.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="SCAN IN PROGRESS", text_color=theme.STATUS_WARN)
        self.result_box.delete("0.0", "end")
        self.assistant_summary.delete("0.0", "end")
        self.assistant_summary.insert("end", "Scan in progress. Metrics will refresh as devices are processed.")
        self._refresh_dashboard_metrics()
        self.db.add_audit_event("scan_started", self.current_user.get("username", "local_operator"), f"Target: {target}")
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()

    def _sync_switches_with_scan(self, data):
        """Reflect real port state: ON = reachable, OFF = closed or blocked by AutoSOC."""
        try:
            open_ports_snapshot = self._extract_open_port_snapshot(data)
            active_ports = {port for _ip, port in open_ports_snapshot}
            blocked_in_firewall = self.firewall.blocked_ports() if self.firewall else set()

            def update_switches_ui():
                for port, switch in self.switches.items():
                    if port in active_ports and port not in blocked_in_firewall:
                        switch.select()
                    else:
                        switch.deselect()

            self._ui(update_switches_ui)
        except Exception as exc:
            log.warning("Switch sync with scan failed: %s", exc)

    def run_scan(self, target):
        try:
            scanner = NetworkScanner()
            data = scanner.scan_network(target, ports=list(self.port_definitions.keys()))
            processed_devices = []

            self._sync_switches_with_scan(data)

            self._append_result(f">>> SCANNING TARGET: {target}\n", "ai")
            self._append_result(
                f">>> Requested scan of {len(self.port_definitions)} tracked TCP ports\n",
                "muted",
            )
            total_risks = 0

            for device in data:
                processed_devices.append(device)
                self.last_scan_data = list(processed_devices)
                self._ui(self._refresh_dashboard_metrics)

                vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Unknown device"
                ip = device.get("ip", "unknown")
                self._append_result(f"\n[DEVICE] {vendor} ({ip})\n", "info")

                open_ports = device.get("ports", [])
                port_summary = device.get("port_scan_summary", {})
                self._append_result(
                    (
                        "    Port scan summary: "
                        f"checked {port_summary.get('requested', len(self.port_definitions))}, "
                        f"open {port_summary.get('open', 0)}, "
                        f"closed {port_summary.get('closed', 0)}, "
                        f"filtered {port_summary.get('filtered', 0)}\n"
                    ),
                    "muted",
                )
                if open_ports:
                    ports_view = ", ".join(
                        f"{item['port']} ({self.port_definitions.get(int(item['port']), item.get('name', 'Unknown'))})"
                        for item in open_ports
                    )
                    self._append_result(f"    Open Ports: {ports_view}\n", "info")
                else:
                    self._append_result("    No open tracked services detected\n", "success")

                risks = self.analyzer.analyze(open_ports)
                for risk in risks:
                    port = risk["port"]
                    service = risk["info"]["service"]
                    if port in self.switches and not self.switches[port].get():
                        self._append_result(
                            f"    Port {port}: firewall switch is OFF, but raw scan still reports OPEN\n",
                            "danger",
                        )

                    total_risks += 1
                    severity = risk["info"]["risk"]
                    self._append_result(f"    Risk: Port {port} ({service}) [{severity}]\n", "danger")
                    instruction = self.ai_expert.generate_instruction(vendor, port, service, "az")
                    self._append_result(f"    Guidance: {instruction}\n", "ai")
                    self._ui(self._refresh_dashboard_metrics)

            findings = self._collect_risks(data)
            risk_score = self.analyzer.calculate_risk_score(findings)
            self.scan_summary = self.nvidia_ai.analyze_ports(target, data)
            if not self.scan_summary:
                if self.nvidia_ai.last_error:
                    self._append_result(f"[NVIDIA AI FALLBACK] {self.nvidia_ai.last_error}\n", "muted")
                self.scan_summary = self.ai_expert.summarize_scan(data, "ru")
            self.last_scan_data = data
            self._set_scan_summary_text(self.scan_summary)
            self._ui(self._refresh_dashboard_metrics)

            new_exposures = self._update_exposure_baseline(data)
            if new_exposures:
                self._append_result("\n[BASELINE DRIFT] Newly exposed services detected since the previous scan:\n", "info")
                for exposure in new_exposures:
                    message = f"    {exposure['ip']} -> port {exposure['port']} ({exposure['service']})\n"
                    self._append_result(message, "info")
                    self.db.add_security_event(
                        "new_exposure",
                        "Medium",
                        exposure["ip"],
                        f"New service exposure detected on port {exposure['port']} ({exposure['service']}).",
                    )
            self._ui(self._refresh_prevention_status)

            telegram_devices = []
            for device in data:
                ip = device.get("ip", "unknown")
                device_ports = device.get("ports", [])
                port_text = ", ".join(str(item["port"]) for item in device_ports) if device_ports else "none"
                telegram_devices.append(f"{ip}: {port_text}")
            telegram_ports_text = "\n".join(telegram_devices[:8]) if telegram_devices else "No devices found"

            if total_risks > 0:
                alert_tg = (
                    f"🔍 *AutoSOC Scan Result*\n\n"
                    f"Target: `{escape_markdown(target)}`\n"
                    f"Detected threats: *{total_risks}*\n"
                    f"Risk score: *{risk_score}%*\n\n"
                    f"*Open ports by device:*\n{escape_markdown(telegram_ports_text)}"
                )
            else:
                self._append_result("\nNo critical issues detected.\n", "success")
                alert_tg = (
                    f"✅ *AutoSOC Scan Result*\n\n"
                    f"Target: `{escape_markdown(target)}`\n"
                    f"Detected threats: *0*\n"
                    f"Risk score: *0%*\n\n"
                    f"*Open ports by device:*\n{escape_markdown(telegram_ports_text)}"
                )
            threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()

            self.db.add_scan(target, risk_score, f"{total_risks} problem(s)")
            self.db.add_audit_event(
                "scan_completed",
                self.current_user.get("username", "local_operator"),
                f"Target: {target}. Risk score: {risk_score}. Threats: {total_risks}.",
            )
        except Exception as exc:
            log.exception("Scan failed for target %s", target)
            self._append_result(f"\n[ERROR] {exc}\n", "danger")
            self.db.add_audit_event(
                "scan_failed",
                self.current_user.get("username", "local_operator"),
                f"Target: {target}. Error: {exc}",
            )
        finally:
            self._ui(lambda: self.btn_scan.configure(state="normal", text="Network Scan"))
            self._set_status("SYSTEM READY", theme.STATUS_OK)
            self._ui(self._refresh_dashboard_metrics)

    # ── AI assistant ─────────────────────────────────────────────────

    def ask_ai_assistant(self, preset_question=None):
        question = (preset_question or self.assistant_entry.get() or "").strip()
        if not question:
            return

        self.assistant_entry.delete(0, "end")
        self._append_chat_message("You", question)
        self._set_chat_controls_state("disabled")

        immediate_action = self._handle_actionable_request(question)
        if immediate_action:
            self._finish_ai_request(immediate_action)
            return

        self.start_ai_loader()
        threading.Thread(target=self._run_ai_request, args=(question,), daemon=True).start()

    def _set_chat_controls_state(self, state):
        self.assistant_button.configure(state=state)
        self.assistant_entry.configure(state=state)

    def _handle_actionable_request(self, question):
        lowered = question.lower()
        port = None
        for known_port in self.port_definitions:
            if str(known_port) in lowered:
                port = known_port
                break

        close_markers = ["close port", "block port", "bağla", "blokla", "закрой порт", "блокируй порт"]
        open_markers = ["open port", "allow port", "aç port", "icazə ver", "открой порт", "разреши порт"]
        secure_markers = ["fix", "secure", "resolve", "remediate", "düzəlt", "həll et", "исправ", "устрани"]

        if any(marker in lowered for marker in ["start canary", "enable canary", "turn on canary", "canary aç", "запусти canary"]):
            if not self.port_canary.is_running:
                self.toggle_port_canary()
            return "I activated the Port Canary decoy listeners to detect suspicious connection attempts early."

        if any(marker in lowered for marker in ["run canary test", "self test", "test attack", "локальный тест canary", "canary test"]):
            self.run_port_canary_self_test()
            return "I launched a safe localhost self-test against the decoy port so we can verify the alert path."

        if port and any(marker in lowered for marker in close_markers):
            switch = self.switches.get(port)
            if switch and switch.get():
                switch.deselect()
                self.toggle_port(port, switch)
            service = self.port_definitions.get(port, "service")
            return f"I blocked port {port} ({service}) in the system firewall and reduced the attack surface."

        if port and any(marker in lowered for marker in open_markers):
            switch = self.switches.get(port)
            if switch and not switch.get():
                switch.select()
                self.toggle_port(port, switch)
            service = self.port_definitions.get(port, "service")
            return f"I allowed port {port} ({service}) in the system firewall."

        if self.last_scan_data and any(marker in lowered for marker in secure_markers + ["şübhəli portları bağla", "close suspicious ports", "закрой опасные порты"]):
            self.harden_risky_ports()
            return "I applied the risky-port hardening routine based on the current scan context."

        return None

    def _run_ai_request(self, question):
        history = self._build_nvidia_chat_history()[:-1]
        answer = self.nvidia_ai.answer_security_question(question, self.last_scan_data, history=history)
        if not answer:
            if self.nvidia_ai.last_error:
                self._append_result(f"[NVIDIA AI FALLBACK] {self.nvidia_ai.last_error}\n", "muted")
            answer = self.ai_expert.answer_question(question, self.last_scan_data)
        self._ui(lambda: self._finish_ai_request(answer))

    def _finish_ai_request(self, answer):
        self.stop_ai_loader()
        self._append_chat_message("AutoSOC", answer)
        self.assistant_summary.delete("0.0", "end")
        self.assistant_summary.insert("end", answer)
        self._set_chat_controls_state("normal")

    def start_ai_loader(self):
        self.ai_loader_step = 0
        self._tick_ai_loader()

    def _tick_ai_loader(self):
        dots = "." * ((self.ai_loader_step % 3) + 1)
        self.assistant_loader.configure(text=f"Analyzing{dots}")
        self.ai_loader_step += 1
        self.ai_loader_job = self.after(350, self._tick_ai_loader)

    def stop_ai_loader(self):
        if self.ai_loader_job:
            self.after_cancel(self.ai_loader_job)
            self.ai_loader_job = None
        self.assistant_loader.configure(text="")

    # ── history windows ──────────────────────────────────────────────

    def show_event_feed(self):
        win = ctk.CTkToplevel(self)
        win.title("Event Feed")
        win.geometry("860x520")
        win.configure(fg_color=theme.BG_FIELD)
        win.attributes("-topmost", True)

        ctk.CTkLabel(
            win,
            text="Security Event Feed",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(20, 8))

        txt = ctk.CTkTextbox(
            win,
            fg_color=theme.BG_CONSOLE,
            corner_radius=16,
            text_color=theme.TEXT_SOFT,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        txt.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        for row in self.db.get_recent_security_events():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}\n")

    def show_history(self):
        win = ctk.CTkToplevel(self)
        win.title("Audit Journal")
        win.geometry("760x500")
        win.configure(fg_color=theme.BG_FIELD)
        win.attributes("-topmost", True)

        ctk.CTkLabel(
            win,
            text="Audit Journal",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(20, 8))

        txt = ctk.CTkTextbox(
            win,
            fg_color=theme.BG_CONSOLE,
            corner_radius=16,
            text_color=theme.TEXT_SOFT,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        txt.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        for row in self.db.get_all_scans():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]}% | {row[3]}\n")
        txt.insert("end", "\n--- Security Events ---\n")
        for row in self.db.get_recent_security_events():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}\n")
        txt.insert("end", "\n--- Audit Events ---\n")
        for row in self.db.get_recent_audit_events():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]} | {row[3]}\n")

    # ── NVIDIA AI engine key ─────────────────────────────────────────

    def _load_nvidia_credentials(self):
        """Apply a saved NVIDIA key/model from settings on top of any .env value."""
        saved_key = (self.db.get_setting("nvidia_api_key", "") or "").strip()
        saved_model = (self.db.get_setting("nvidia_model", "") or "").strip()
        if saved_key or saved_model:
            self.nvidia_ai.configure(
                api_key=saved_key or None,
                model=saved_model or None,
            )
        self.nvidia_api_key = self.nvidia_ai.api_key
        self.nvidia_model = self.nvidia_ai.model

    def toggle_nvidia_key_visibility(self):
        showing = self.nvidia_key_entry.cget("show") == ""
        self.nvidia_key_entry.configure(show="•" if showing else "")
        self.btn_show_key.configure(text="Show" if showing else "Hide")

    def save_nvidia_key(self):
        key = self.nvidia_key_entry.get().strip()
        model = self.nvidia_model_entry.get().strip()
        self.nvidia_ai.configure(api_key=key, model=model or None)
        self.nvidia_api_key = self.nvidia_ai.api_key
        self.nvidia_model = self.nvidia_ai.model
        # The API key is a secret; it is stored in the per-user, owner-only DB.
        self.db.set_setting("nvidia_api_key", key)
        if model:
            self.db.set_setting("nvidia_model", model)
        self.db.add_audit_event(
            "nvidia_key_updated",
            self.current_user.get("username", "local_operator"),
            f"NVIDIA AI engine key {'set' if key else 'cleared'}; model={self.nvidia_ai.model}.",
        )
        self._refresh_nvidia_key_status()
        if key:
            threading.Thread(target=self._verify_nvidia_key, daemon=True).start()

    def _verify_nvidia_key(self):
        answer = self.nvidia_ai.answer_security_question("Reply with the single word: OK")
        if answer:
            self._ui(lambda: self.nvidia_key_status.configure(
                text=f"AI engine active · model {self.nvidia_ai.model}", text_color=theme.STATUS_GOOD))
        else:
            reason = self.nvidia_ai.last_error or "no response"
            self._ui(lambda: self.nvidia_key_status.configure(
                text=f"Key saved but test failed: {reason}", text_color=theme.STATUS_WARN))

    def _refresh_nvidia_key_status(self):
        if not hasattr(self, "nvidia_key_status"):
            return
        if self.nvidia_ai.enabled:
            self.nvidia_key_status.configure(
                text=f"AI engine configured · model {self.nvidia_ai.model}",
                text_color=theme.STATUS_GOOD,
            )
        else:
            self.nvidia_key_status.configure(
                text="No key set — copilot and AI phishing verdict run in offline/heuristic mode.",
                text_color=theme.TEXT_FAINT,
            )

    # ── Anti-phishing tab ────────────────────────────────────────────

    def analyze_phishing_url(self, deep=True):
        raw_url = self.phishing_url_entry.get().strip()
        if not raw_url:
            self.phishing_status.configure(text="Enter a URL first.", text_color=theme.STATUS_WARN)
            return

        self.btn_phishing_analyze.configure(state="disabled")
        self.btn_phishing_quick.configure(state="disabled")
        self.btn_phishing_to_case.configure(state="disabled")
        mode = "Full analysis (fetching page, TLS, spelling, AI)" if deep else "Quick offline heuristics"
        self.phishing_status.configure(text=f"{mode} for {raw_url} …", text_color=theme.STATUS_WARN)
        threading.Thread(target=self._run_phishing_analysis, args=(raw_url, deep), daemon=True).start()

    def _run_phishing_analysis(self, raw_url, deep):
        try:
            if deep:
                report = self.phishing_analyzer.full_scan(raw_url, use_ai=self.nvidia_ai.enabled)
            else:
                report = self.phishing_analyzer.quick_scan(raw_url)
        except Exception as exc:
            log.exception("Phishing analysis failed for %s", raw_url)
            self._ui(lambda: self.phishing_status.configure(
                text=f"Analysis failed: {exc}", text_color=theme.STATUS_ERROR))
            self._ui(lambda: self._reset_phishing_buttons())
            return

        self.last_phishing_report = report
        self.db.add_audit_event(
            "phishing_scan",
            self.current_user.get("username", "local_operator"),
            f"URL: {report.url}. Score: {report.score}. Verdict: {report.verdict}.",
        )
        if report.score >= 55:
            self.db.add_security_event(
                "phishing_suspected", "High" if report.score >= 80 else "Medium",
                report.host or report.url,
                f"Phishing analysis flagged {report.url} (score {report.score}, {report.verdict}).",
            )
        self._ui(lambda: self._render_phishing_report(report))

    def _reset_phishing_buttons(self):
        self.btn_phishing_analyze.configure(state="normal")
        self.btn_phishing_quick.configure(state="normal")

    def _render_phishing_report(self, report):
        self._reset_phishing_buttons()

        for child in self.phishing_signals_frame.winfo_children():
            child.destroy()

        color = self._phishing_verdict_color(report.score)
        self.phishing_score_label.configure(text=str(report.score), text_color=color)
        self.phishing_verdict_label.configure(text=report.verdict.upper(), text_color=color)
        self.phishing_score_bar.configure(progress_color=color)
        self.phishing_score_bar.set(report.score / 100)

        detail = report.verdict_detail
        if report.final_url and report.final_url != report.url:
            detail += f"\nFinal URL: {report.final_url}"
        if report.fetch_error:
            detail += f"\nFetch note: {report.fetch_error}"
        self.phishing_verdict_detail.configure(text=detail)

        hits = report.hits()
        reassuring = [s for s in report.signals if not s.hit]
        if not hits and not reassuring:
            ctk.CTkLabel(
                self.phishing_signals_frame,
                text="No signals produced.",
                text_color=theme.TEXT_MUTED,
                font=ctk.CTkFont(size=12),
            ).grid(row=0, column=0, sticky="w", padx=12, pady=12)
        row_index = 0
        for signal in hits:
            self._phishing_signal_row(row_index, signal, risky=True)
            row_index += 1
        for signal in reassuring:
            self._phishing_signal_row(row_index, signal, risky=False)
            row_index += 1

        self.phishing_ai_box.configure(state="normal")
        self.phishing_ai_box.delete("0.0", "end")
        if report.ai_used and report.ai_summary:
            self.phishing_ai_box.insert("end", f"AI verdict:\n{report.ai_summary}")
        elif self.nvidia_ai.enabled:
            self.phishing_ai_box.insert("end", "AI verdict unavailable (model returned nothing or quick scan was used).")
        else:
            self.phishing_ai_box.insert("end", "AI verdict disabled — add a NVIDIA API key in the left panel for a deep language check of the page text.")
        self.phishing_ai_box.configure(state="disabled")

        self.btn_phishing_to_case.configure(state="normal")
        self.phishing_status.configure(
            text=f"Done · {len(hits)} risk signal(s) · score {report.score}/100 ({report.verdict}).",
            text_color=color,
        )

    def _phishing_signal_row(self, row_index, signal, risky):
        frame = ctk.CTkFrame(self.phishing_signals_frame, fg_color="transparent")
        frame.grid(row=row_index, column=0, sticky="ew", padx=10, pady=(6, 0))
        frame.grid_columnconfigure(1, weight=1)

        dot_color = self._phishing_category_color(signal.category) if risky else theme.ACCENT_GREEN
        ctk.CTkLabel(frame, text="●", text_color=dot_color, font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, sticky="nw", padx=(0, 8))

        text_stack = ctk.CTkFrame(frame, fg_color="transparent")
        text_stack.grid(row=0, column=1, sticky="ew")
        weight_txt = f"  (+{signal.weight})" if risky else "  (ok)"
        ctk.CTkLabel(
            text_stack,
            text=f"[{signal.category}] {signal.title}{weight_txt}",
            text_color=theme.TEXT_SOFT if risky else theme.TEXT_MUTED,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
            justify="left",
        ).pack(anchor="w", fill="x")
        ctk.CTkLabel(
            text_stack,
            text=signal.detail,
            text_color="#85a3bd",
            font=ctk.CTkFont(size=11),
            wraplength=430,
            justify="left",
            anchor="w",
        ).pack(anchor="w", fill="x")

    @staticmethod
    def _phishing_verdict_color(score):
        if score >= 80:
            return theme.STATUS_DANGER
        if score >= 55:
            return "#ff9f6e"
        if score >= 30:
            return theme.ACCENT_YELLOW
        return theme.ACCENT_GREEN

    @staticmethod
    def _phishing_category_color(category):
        return {
            "URL": theme.ACCENT_CYAN,
            "TLS": "#c58fff",
            "Content": "#ff9f6e",
            "Spelling": theme.ACCENT_YELLOW,
            "Reputation": theme.STATUS_DANGER,
            "AI": "#8fbfff",
        }.get(category, theme.ACCENT_YELLOW)

    def send_phishing_to_case(self):
        report = self.last_phishing_report
        if not report:
            return
        top_signals = "; ".join(f"{s.title}" for s in report.hits()[:6]) or "no risk signals"
        summary = (
            f"Phishing analysis of {report.url}\n"
            f"Score: {report.score}/100 ({report.verdict})\n"
            f"Host: {report.host}\n"
            f"Top signals: {top_signals}"
        )
        if report.ai_summary:
            summary += f"\nAI: {report.ai_summary}"
        severity = "Critical" if report.score >= 80 else "High" if report.score >= 55 else "Medium"
        incident_id = self.db.create_incident(
            title=f"Suspected phishing: {report.host or report.url}",
            severity=severity,
            source="anti-phishing",
            summary=summary,
            created_by=self.current_user.get("username", "local_operator"),
        )
        self.db.add_audit_event(
            "incident_created",
            self.current_user.get("username", "local_operator"),
            f"Incident #{incident_id} from phishing analysis of {report.url}.",
        )
        self.phishing_status.configure(
            text=f"Saved as SOC incident #{incident_id}. Open the SOC Console to triage it.",
            text_color=theme.STATUS_GOOD,
        )
        if self.soc_console is not None and self.soc_console.winfo_exists():
            self.soc_console.refresh_all()

    # ── SOC console ──────────────────────────────────────────────────

    def open_soc_console(self):
        from autosoc.ui.soc_console import SOCConsoleWindow

        if self.soc_console is not None and self.soc_console.winfo_exists():
            self.soc_console.deiconify()
            self.soc_console.lift()
            self.soc_console.focus_force()
            return
        self.soc_console = SOCConsoleWindow(self, self.db, self.current_user)

    # ── endpoint collector ───────────────────────────────────────────

    def start_collector(self):
        from autosoc.agents.server import CollectorService

        if self.collector is None:
            self.collector = CollectorService(self.db)
        ok, message = self.collector.start()
        self.db.add_audit_event(
            "collector_started" if ok else "collector_start_failed",
            self.current_user.get("username", "local_operator"),
            message,
        )
        return ok, message

    def stop_collector(self):
        if self.collector is not None and self.collector.running:
            self.collector.stop()
            self.db.add_audit_event("collector_stopped",
                                    self.current_user.get("username", "local_operator"),
                                    "Endpoint collector stopped.")

    def collector_running(self):
        return bool(self.collector is not None and self.collector.running)

    def collector_bind(self):
        if self.collector is not None:
            return self.collector.address()
        from autosoc.agents.server import DEFAULT_PORT

        return ("0.0.0.0", int(os.getenv("AUTOSOC_COLLECTOR_PORT") or DEFAULT_PORT))

    def collector_lan_url(self):
        """A URL an endpoint on the LAN can actually reach (never 0.0.0.0)."""
        _host, port = self.collector_bind()
        return f"http://{self._primary_lan_ip()}:{port}"

    @staticmethod
    def _primary_lan_ip():
        """The source IP this host uses to reach the network (real LAN address)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return "127.0.0.1"
        finally:
            sock.close()

    def collector_token(self):
        return self.db.get_or_create_ingestion_token()

    def regenerate_collector_token(self):
        token = self.db.regenerate_ingestion_token()
        self.db.add_audit_event("ingestion_token_regenerated",
                                self.current_user.get("username", "local_operator"),
                                "Agent ingestion token regenerated.")
        return token

    # ── syslog ingestion ─────────────────────────────────────────────

    def start_syslog(self):
        from autosoc.agents.syslog_server import SyslogService

        if self.syslog is None:
            self.syslog = SyslogService(self.db, on_detection=self.on_bruteforce_detected)
        ok, message = self.syslog.start()
        self.db.add_audit_event(
            "syslog_started" if ok else "syslog_start_failed",
            self.current_user.get("username", "local_operator"),
            message,
        )
        return ok, message

    def stop_syslog(self):
        if self.syslog is not None and self.syslog.running:
            self.syslog.stop()
            self.db.add_audit_event("syslog_stopped",
                                    self.current_user.get("username", "local_operator"),
                                    "Syslog receiver stopped.")

    def syslog_running(self):
        return bool(self.syslog is not None and self.syslog.running)

    def syslog_bind(self):
        if self.syslog is not None:
            return self.syslog.address()
        from autosoc.agents.syslog_server import DEFAULT_SYSLOG_PORT

        return ("0.0.0.0", int(os.getenv("AUTOSOC_SYSLOG_PORT") or DEFAULT_SYSLOG_PORT))

    def syslog_target(self):
        _host, port = self.syslog_bind()
        return f"{self._primary_lan_ip()}:{port}/udp"

    def blocklist_feed_url(self):
        _host, port = self.collector_bind()
        return f"http://{self._primary_lan_ip()}:{port}/blocklist.txt"

    # ── firewall appliance integration ───────────────────────────────

    def get_firewall_config(self):
        return {
            "type": (self.db.get_setting("firewall_type", "") or "").strip(),
            "host": self.db.get_setting("firewall_host", "") or "",
            "token": self.db.get_setting("firewall_token", "") or "",
            "vdom": self.db.get_setting("firewall_vdom", "root") or "root",
            "group": self.db.get_setting("firewall_group", "AutoSOC_Blocklist") or "AutoSOC_Blocklist",
        }

    def save_firewall_config(self, fw_type, host, token, vdom, group):
        self.db.set_setting("firewall_type", (fw_type or "").strip().lower())
        self.db.set_setting("firewall_host", (host or "").strip())
        self.db.set_setting("firewall_token", (token or "").strip())
        self.db.set_setting("firewall_vdom", (vdom or "root").strip() or "root")
        self.db.set_setting("firewall_group", (group or "AutoSOC_Blocklist").strip() or "AutoSOC_Blocklist")
        self.db.add_audit_event(
            "firewall_integration_saved",
            self.current_user.get("username", "local_operator"),
            f"Firewall integration set to '{(fw_type or 'none').lower()}'.",
        )

    def test_firewall_config(self):
        from autosoc.system.appliance import connector_from_settings

        return connector_from_settings(self.db).test_connection()

    def block_ip_everywhere(self, ip, reason="manual"):
        return self.response.block_ip(ip, reason=reason,
                                      actor=self.current_user.get("username", "autosoc"))

    def unblock_ip_everywhere(self, ip):
        return self.response.unblock_ip(ip, actor=self.current_user.get("username", "autosoc"))
