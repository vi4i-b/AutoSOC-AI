import json
import math
import os
import socket
import threading
import time
import webbrowser

import customtkinter as ctk
import requests
from tkinter import messagebox

from ai_expert import AISecurityExpert
from analyzer import RiskAnalyzer
from database import SOCDatabase
from guard import NetworkGuard
from scanner import NetworkScanner

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def load_env_file(path=".env"):
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError:
        pass


class TelegramBotClient:
    def __init__(self, token):
        self.token = (token or "").strip()
        self.base_url = f"https://api.telegram.org/bot{self.token}" if self.token else ""
        self.enabled = bool(self.token)

    def get_me(self):
        if not self.enabled:
            return False, {"description": "Telegram bot token is empty"}
        return self._request("getMe", method="get")

    def send_message(self, chat_id, text, parse_mode="Markdown"):
        if not self.enabled:
            return False, {"description": "Telegram bot token is empty"}
        payload = {"chat_id": str(chat_id), "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        return self._request("sendMessage", method="post", payload=payload)

    def get_updates(self, offset=None, timeout=25):
        if not self.enabled:
            return False, {"description": "Telegram bot token is empty"}
        payload = {"timeout": timeout}
        if offset is not None:
            payload["offset"] = offset
        return self._request("getUpdates", method="get", payload=payload, timeout=timeout + 10)

    def _request(self, method_name, method="get", payload=None, timeout=30):
        try:
            if method == "post":
                response = requests.post(f"{self.base_url}/{method_name}", json=payload or {}, timeout=timeout)
            else:
                response = requests.get(f"{self.base_url}/{method_name}", params=payload or {}, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            return bool(data.get("ok")), data
        except Exception as exc:
            return False, {"description": str(exc)}


class AutoSOCApp(ctk.CTk):
    FAQ_ITEMS = [
        "445 portu niyə təhlükəlidir?",
        "Son scan nəticəsini izah et",
        "RDP açıqdırsa nə etməliyəm?",
        "Fişinqdən necə qorunum?",
        "Şübhəli portları bağla",
        "Explain the current risk posture",
    ]

    def __init__(self):
        super().__init__()
        load_env_file()

        self.db = SOCDatabase()
        saved_chat_id = self.db.get_setting("telegram_chat_id", "").strip()
        latest_tg_user = self.db.get_latest_telegram_user()
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = saved_chat_id or os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if not self.chat_id and latest_tg_user:
            self.chat_id = str(latest_tg_user[1])

        self.telegram_bot_url = os.getenv("TELEGRAM_BOT_URL", "https://t.me/AutoSOC_Baku_Bot").strip()
        self.telegram_client = TelegramBotClient(self.bot_token)
        self.telegram_listener_running = False
        self.telegram_offset = None
        self.bot_identity = None

        self.ai_expert = AISecurityExpert()
        self.guard = NetworkGuard(self.on_threat_detected)
        self.last_scan_data = []
        self.scan_summary = ""
        self.ai_chat_window = None
        self.ai_loader_job = None
        self.ai_loader_step = 0
        self.ai_fab_animation_tick = 0
        self.chat_history = []

        self.title("AutoSOC AI: Cyber Shield v3.0")
        self.geometry("1440x960")
        self.minsize(1280, 840)
        self.configure(fg_color="#07111b")

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.port_definitions = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            1433: "MS-SQL",
            1521: "Oracle DB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        self.switches = {}

        self._build_sidebar()
        self._build_main_panel()
        self._build_fab()
        self._render_intro_message()
        self._refresh_dashboard_metrics()
        self._check_telegram_status()

        if self.telegram_client.enabled:
            self.start_telegram_listener()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=330, fg_color="#0b1623", corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="#0f2033", corner_radius=20)
        brand.pack(fill="x", padx=22, pady=(22, 16))
        ctk.CTkLabel(
            brand,
            text="AutoSOC AI",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#f2f7fb",
        ).pack(anchor="w", padx=18, pady=(18, 2))
        ctk.CTkLabel(
            brand,
            text="SOC cockpit for network visibility, response, and Telegram alerting",
            font=ctk.CTkFont(size=12),
            text_color="#8ea8bf",
            wraplength=250,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 18))

        control_card = ctk.CTkFrame(self.sidebar, fg_color="#101c2b", corner_radius=18)
        control_card.pack(fill="x", padx=22, pady=(0, 16))

        self.btn_scan = ctk.CTkButton(
            control_card,
            text="Network Scan",
            height=48,
            corner_radius=14,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.start_scan_thread,
        )
        self.btn_scan.pack(fill="x", padx=16, pady=(16, 10))

        self.btn_guard = ctk.CTkButton(
            control_card,
            text="AI Guard: Off",
            height=46,
            corner_radius=14,
            fg_color="#243244",
            hover_color="#31445b",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.toggle_guard,
        )
        self.btn_guard.pack(fill="x", padx=16, pady=(0, 10))

        self.btn_history = ctk.CTkButton(
            control_card,
            text="Audit Journal",
            height=42,
            corner_radius=14,
            fg_color="transparent",
            hover_color="#172433",
            border_width=1,
            border_color="#2b425a",
            command=self.show_history,
        )
        self.btn_history.pack(fill="x", padx=16, pady=(0, 16))

        sensitivity_card = ctk.CTkFrame(self.sidebar, fg_color="#101c2b", corner_radius=18)
        sensitivity_card.pack(fill="x", padx=22, pady=(0, 16))

        self.slider_label = ctk.CTkLabel(
            sensitivity_card,
            text="DDoS Sensitivity: 500",
            text_color="#d9e5f1",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.slider_label.pack(anchor="w", padx=16, pady=(16, 6))

        self.threshold_slider = ctk.CTkSlider(
            sensitivity_card,
            from_=50,
            to=2000,
            command=self.update_threshold,
            progress_color="#2b7fff",
            button_color="#b5d0ff",
            button_hover_color="#dce9ff",
        )
        self.threshold_slider.pack(fill="x", padx=16, pady=(0, 12))
        self.threshold_slider.set(500)

        ctk.CTkLabel(
            sensitivity_card,
            text="Lower values react faster. Higher values reduce false positives.",
            text_color="#7f95ab",
            font=ctk.CTkFont(size=11),
            wraplength=250,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 16))

        ports_card = ctk.CTkFrame(self.sidebar, fg_color="#101c2b", corner_radius=18)
        ports_card.pack(fill="both", expand=True, padx=22, pady=(0, 16))

        ctk.CTkLabel(
            ports_card,
            text="Port Control",
            text_color="#e8f1f8",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(16, 8))

        actions_row = ctk.CTkFrame(ports_card, fg_color="transparent")
        actions_row.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkButton(
            actions_row,
            text="Allow All",
            width=120,
            height=34,
            corner_radius=12,
            fg_color="#1f805d",
            hover_color="#166446",
            command=self.enable_all_ports,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            actions_row,
            text="Block All",
            width=120,
            height=34,
            corner_radius=12,
            fg_color="#88344d",
            hover_color="#6d263c",
            command=self.disable_all_ports,
        ).pack(side="left")

        self.ports_frame = ctk.CTkScrollableFrame(
            ports_card,
            fg_color="#0c1623",
            corner_radius=14,
            height=300,
        )
        self.ports_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for port, service in sorted(self.port_definitions.items()):
            switch = ctk.CTkSwitch(
                self.ports_frame,
                text=f"Port {port}  •  {service}",
                progress_color="#2b7fff",
                button_color="#d2e3ff",
                button_hover_color="#f3f8ff",
                command=lambda p=port: self.toggle_port(p, self.switches[p]),
            )
            switch.pack(anchor="w", padx=10, pady=4)
            switch.select()
            self.switches[port] = switch

        telegram_card = ctk.CTkFrame(self.sidebar, fg_color="#101c2b", corner_radius=18)
        telegram_card.pack(fill="x", padx=22, pady=(0, 22))

        ctk.CTkLabel(
            telegram_card,
            text="Telegram Alerts",
            text_color="#e8f1f8",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(16, 6))

        self.tg_entry = ctk.CTkEntry(
            telegram_card,
            height=40,
            corner_radius=12,
            placeholder_text="Telegram Chat ID",
            fg_color="#0a1522",
            border_color="#29425c",
        )
        self.tg_entry.pack(fill="x", padx=16, pady=(0, 8))
        if self.chat_id:
            self.tg_entry.insert(0, self.chat_id)

        self.tg_status = ctk.CTkLabel(
            telegram_card,
            text="Waiting for Telegram configuration",
            text_color="#87a5c0",
            font=ctk.CTkFont(size=11),
            justify="left",
            wraplength=250,
        )
        self.tg_status.pack(anchor="w", padx=16, pady=(0, 10))

        btn_row = ctk.CTkFrame(telegram_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 8))

        self.btn_save_tg = ctk.CTkButton(
            btn_row,
            text="Save & Test",
            width=115,
            height=36,
            corner_radius=12,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            command=self.save_telegram_id,
        )
        self.btn_save_tg.pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row,
            text="Open Bot",
            width=115,
            height=36,
            corner_radius=12,
            fg_color="transparent",
            hover_color="#172433",
            border_width=1,
            border_color="#2b425a",
            command=lambda: webbrowser.open(self.telegram_bot_url),
        ).pack(side="left")

        self.btn_resync_tg = ctk.CTkButton(
            telegram_card,
            text="Resync /start Listener",
            height=34,
            corner_radius=12,
            fg_color="#243244",
            hover_color="#31445b",
            command=self.restart_telegram_listener,
        )
        self.btn_resync_tg.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkLabel(
            telegram_card,
            text="Write /start to the bot. The app will capture the Chat ID and use it for notifications.",
            text_color="#7f95ab",
            font=ctk.CTkFont(size=11),
            wraplength=250,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 16))

    def _build_main_panel(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="#07111b", corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.topbar = ctk.CTkFrame(self.main_frame, fg_color="#07111b", corner_radius=0)
        self.topbar.grid(row=0, column=0, sticky="ew", padx=26, pady=(24, 14))
        self.topbar.grid_columnconfigure(0, weight=1)

        title_block = ctk.CTkFrame(self.topbar, fg_color="transparent")
        title_block.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            title_block,
            text="Security Operations Dashboard",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color="#f4f8fc",
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_block,
            text="Elegant operational visibility with guided AI support in Azerbaijani, Russian, and English",
            font=ctk.CTkFont(size=13),
            text_color="#85a3bd",
        ).pack(anchor="w", pady=(4, 0))

        actions = ctk.CTkFrame(self.topbar, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e")

        self.ip_entry = ctk.CTkEntry(
            actions,
            width=300,
            height=44,
            corner_radius=14,
            placeholder_text="Target IP or host",
            fg_color="#0d1824",
            border_color="#2c445b",
            font=ctk.CTkFont(size=13),
        )
        self.ip_entry.pack(side="left", padx=(0, 10))
        try:
            self.ip_entry.insert(0, socket.gethostbyname(socket.gethostname()))
        except Exception:
            self.ip_entry.insert(0, "127.0.0.1")

        ctk.CTkButton(
            actions,
            text="Start Scan",
            width=130,
            height=44,
            corner_radius=14,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            command=self.start_scan_thread,
        ).pack(side="left")

        metrics = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        metrics.grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 14))
        for idx in range(4):
            metrics.grid_columnconfigure(idx, weight=1)

        self.metric_total_devices = self._metric_card(metrics, 0, "Devices", "0", "#4cc9f0")
        self.metric_open_ports = self._metric_card(metrics, 1, "Open Ports", "0", "#5dd39e")
        self.metric_risk = self._metric_card(metrics, 2, "Risk Score", "0%", "#ff9f6e")
        self.metric_tg = self._metric_card(metrics, 3, "Telegram", "Offline", "#ff6b7a")

        content = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        content.grid(row=2, column=0, sticky="nsew", padx=26, pady=(0, 26))
        content.grid_columnconfigure(0, weight=7)
        content.grid_columnconfigure(1, weight=5)
        content.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(content, fg_color="#0b1623", corner_radius=22)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        terminal_header = ctk.CTkFrame(left, fg_color="transparent")
        terminal_header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 10))
        terminal_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            terminal_header,
            text="Scan Console",
            text_color="#f2f7fb",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        self.status_label = ctk.CTkLabel(
            terminal_header,
            text="SYSTEM READY",
            text_color="#6bf0a7",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.status_label.grid(row=0, column=1, sticky="e")

        self.result_box = ctk.CTkTextbox(
            left,
            fg_color="#07111b",
            corner_radius=18,
            border_color="#1f3449",
            border_width=1,
            text_color="#dbe8f4",
            font=ctk.CTkFont(family="Consolas", size=13),
        )
        self.result_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.result_box.tag_config("danger", foreground="#ff7c85")
        self.result_box.tag_config("success", foreground="#66e0a3")
        self.result_box.tag_config("ai", foreground="#77beff")
        self.result_box.tag_config("info", foreground="#ffd36b")
        self.result_box.tag_config("muted", foreground="#8ca3b8")

        right = ctk.CTkFrame(content, fg_color="#0b1623", corner_radius=22)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)
        right.grid_columnconfigure(0, weight=1)

        summary_card = ctk.CTkFrame(right, fg_color="#0d1b2a", corner_radius=18)
        summary_card.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 12))

        ctk.CTkLabel(
            summary_card,
            text="AI Situation Brief",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(14, 8))

        self.assistant_summary = ctk.CTkTextbox(
            summary_card,
            height=130,
            fg_color="#08111b",
            corner_radius=16,
            text_color="#d8e6f3",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.assistant_summary.pack(fill="x", padx=16, pady=(0, 14))

        faq_card = ctk.CTkFrame(right, fg_color="#0d1b2a", corner_radius=18)
        faq_card.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 12))

        ctk.CTkLabel(
            faq_card,
            text="Smart Prompts",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(14, 10))

        self.faq_buttons_frame = ctk.CTkFrame(faq_card, fg_color="transparent")
        self.faq_buttons_frame.pack(fill="x", padx=12, pady=(0, 12))
        self._build_faq_buttons(self.faq_buttons_frame)

        chat_card = ctk.CTkFrame(right, fg_color="#0d1b2a", corner_radius=18)
        chat_card.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        chat_card.grid_rowconfigure(1, weight=1)
        chat_card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(chat_card, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="AI Copilot",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        self.assistant_loader = ctk.CTkLabel(
            header,
            text="",
            text_color="#8fbfff",
            font=ctk.CTkFont(size=11),
        )
        self.assistant_loader.grid(row=0, column=1, sticky="e")

        self.assistant_output = ctk.CTkTextbox(
            chat_card,
            fg_color="#08111b",
            corner_radius=16,
            border_color="#1d3347",
            border_width=1,
            text_color="#dce8f2",
            font=ctk.CTkFont(size=12),
            wrap="word",
        )
        self.assistant_output.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))

        prompt_row = ctk.CTkFrame(chat_card, fg_color="transparent")
        prompt_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        prompt_row.grid_columnconfigure(0, weight=1)

        self.assistant_entry = ctk.CTkEntry(
            prompt_row,
            height=42,
            corner_radius=14,
            placeholder_text="Ask in Azerbaijani, Russian, or English",
            fg_color="#101b28",
            border_color="#2c445b",
        )
        self.assistant_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.assistant_entry.bind("<Return>", lambda e: self.ask_ai_assistant())

        self.assistant_button = ctk.CTkButton(
            prompt_row,
            text="Send",
            width=95,
            height=42,
            corner_radius=14,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            command=self.ask_ai_assistant,
        )
        self.assistant_button.grid(row=0, column=1, sticky="e")

    def _build_fab(self):
        self.ai_fab = ctk.CTkButton(
            self,
            text="AI\nChat",
            width=82,
            height=82,
            corner_radius=41,
            fg_color="#77beff",
            hover_color="#a1d1ff",
            text_color="#04131f",
            font=ctk.CTkFont(size=16, weight="bold"),
            border_width=3,
            border_color="#d9ecff",
            command=self.open_ai_chat_window,
        )
        self.ai_fab.place(relx=1.0, rely=1.0, x=-34, y=-34, anchor="se")
        self.after(80, self.animate_ai_fab)

    def _metric_card(self, parent, column, label, value, accent):
        card = ctk.CTkFrame(parent, fg_color="#0b1623", corner_radius=20)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0 if column == 3 else 8))
        ctk.CTkLabel(
            card,
            text=label,
            text_color="#87a5c0",
            font=ctk.CTkFont(size=12),
        ).pack(anchor="w", padx=16, pady=(14, 6))
        value_label = ctk.CTkLabel(
            card,
            text=value,
            text_color=accent,
            font=ctk.CTkFont(size=26, weight="bold"),
        )
        value_label.pack(anchor="w", padx=16, pady=(0, 14))
        return value_label

    def _build_faq_buttons(self, parent):
        for index, question in enumerate(self.FAQ_ITEMS):
            row = index // 2
            col = index % 2
            parent.grid_columnconfigure(col, weight=1)
            button = ctk.CTkButton(
                parent,
                text=question,
                height=36,
                corner_radius=12,
                fg_color="#142433",
                hover_color="#1d3348",
                text_color="#dce8f2",
                font=ctk.CTkFont(size=11),
                command=lambda q=question: self.ask_ai_assistant(q),
            )
            button.grid(row=row, column=col, sticky="ew", padx=4, pady=4)

    def _render_intro_message(self):
        intro = (
            "AutoSOC AI hazırdır.\n\n"
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
            prefix = "You" if sender_name == "You" else "AutoSOC AI"
            self.assistant_output.insert("end", f"{prefix}\n{content}\n\n")
        self.assistant_output.see("end")

    def _refresh_dashboard_metrics(self):
        total_devices = len(self.last_scan_data)
        open_ports = sum(len(device.get("ports", [])) for device in self.last_scan_data)
        risk_count = len(self._collect_risks(self.last_scan_data))
        risk_score = min(risk_count * 25, 100)

        self.metric_total_devices.configure(text=str(total_devices))
        self.metric_open_ports.configure(text=str(open_ports))
        self.metric_risk.configure(text=f"{risk_score}%")

        if self.telegram_client.enabled and self.chat_id:
            self.metric_tg.configure(text="Ready", text_color="#6de0a8")
        elif self.telegram_client.enabled:
            self.metric_tg.configure(text="No Chat ID", text_color="#ffd36b")
        else:
            self.metric_tg.configure(text="Offline", text_color="#ff7c85")

    def _check_telegram_status(self):
        if not self.telegram_client.enabled:
            self.tg_status.configure(
                text="Telegram bot token tapılmadı. .env faylında TELEGRAM_BOT_TOKEN əlavə edin.",
                text_color="#ff8a8a",
            )
            return

        ok, data = self.telegram_client.get_me()
        if ok:
            username = data.get("result", {}).get("username", "bot")
            self.bot_identity = username
            text = f"Bot online: @{username}"
            if self.chat_id:
                text += f"\nActive chat_id: {self.chat_id}"
            self.tg_status.configure(text=text, text_color="#7fe3b1")
        else:
            self.tg_status.configure(
                text=f"Telegram xətası: {data.get('description', 'unknown error')}",
                text_color="#ff8a8a",
            )
        self._refresh_dashboard_metrics()

    def _collect_risks(self, data):
        analyzer = RiskAnalyzer()
        risks = []
        for device in data or []:
            risks.extend(analyzer.analyze(device.get("ports", [])))
        return risks

    def enable_all_ports(self):
        for port, switch in self.switches.items():
            if not switch.get():
                switch.select()
                self.toggle_port(port, switch)
        self.result_box.insert("0.0", "[FIREWALL] All tracked ports allowed\n", "success")

    def disable_all_ports(self):
        for port, switch in self.switches.items():
            if switch.get():
                switch.deselect()
                self.toggle_port(port, switch)
        self.result_box.insert("0.0", "[FIREWALL] All tracked ports blocked\n", "danger")

    def save_telegram_id(self):
        new_id = self.tg_entry.get().strip()
        if not new_id:
            self.tg_status.configure(text="Chat ID is empty.", text_color="#ff8a8a")
            return
        if not self._looks_like_chat_id(new_id):
            self.tg_status.configure(text="Chat ID format looks invalid.", text_color="#ff8a8a")
            return

        self.chat_id = new_id
        self.db.set_setting("telegram_chat_id", self.chat_id)
        self.tg_status.configure(text="Testing Telegram connection...", text_color="#ffd36b")
        self._refresh_dashboard_metrics()
        threading.Thread(target=self._send_test_message, daemon=True).start()

    def _send_test_message(self):
        ok, data = self.telegram_client.send_message(
            self.chat_id,
            "✅ *AutoSOC AI connected*\nTelegram notifications are now linked to this chat.",
        )
        if ok:
            self.after(0, lambda: self.tg_status.configure(
                text=f"Chat ID verified successfully.\nActive chat_id: {self.chat_id}",
                text_color="#7fe3b1",
            ))
            self.after(0, self._refresh_dashboard_metrics)
        else:
            self.after(0, lambda: self.tg_status.configure(
                text=f"Telegram send failed: {data.get('description', 'unknown error')}",
                text_color="#ff8a8a",
            ))

    def send_telegram_alert(self, message_text):
        if not self.chat_id:
            return
        ok, data = self.telegram_client.send_message(self.chat_id, message_text)
        if not ok:
            self.after(0, lambda: self.result_box.insert(
                "0.0",
                f"[TELEGRAM ERROR] {data.get('description', 'unknown error')}\n",
                "danger",
            ))

    def start_telegram_listener(self):
        if self.telegram_listener_running or not self.telegram_client.enabled:
            return
        self.telegram_listener_running = True
        threading.Thread(target=self._telegram_polling_loop, daemon=True).start()

    def restart_telegram_listener(self):
        self.telegram_listener_running = False
        self.after(1200, self.start_telegram_listener)
        self.tg_status.configure(text="Telegram listener restarting...", text_color="#ffd36b")

    def _telegram_polling_loop(self):
        while self.telegram_client.enabled and self.telegram_listener_running:
            ok, data = self.telegram_client.get_updates(offset=self.telegram_offset, timeout=20)
            if not ok:
                description = data.get("description", "unknown error")
                self.after(0, lambda d=description: self.tg_status.configure(
                    text=f"Telegram listener error: {d}",
                    text_color="#ff8a8a",
                ))
                time.sleep(4)
                continue

            for update in data.get("result", []):
                update_id = update.get("update_id")
                if update_id is not None:
                    self.telegram_offset = update_id + 1
                self._handle_telegram_update(update)

    def _handle_telegram_update(self, update):
        message = update.get("message") or update.get("edited_message")
        if not message:
            return

        text = (message.get("text") or "").strip()
        if not text.startswith("/"):
            return

        chat_id = message.get("chat", {}).get("id")
        from_user = message.get("from", {})
        user_id = from_user.get("id")

        raw_payload = json.dumps(update, ensure_ascii=False)
        if user_id is not None and chat_id is not None:
            self.db.upsert_telegram_user(
                telegram_user_id=str(user_id),
                telegram_chat_id=str(chat_id),
                username=from_user.get("username", ""),
                first_name=from_user.get("first_name", ""),
                last_name=from_user.get("last_name", ""),
                raw_payload=raw_payload,
            )
            self.chat_id = str(chat_id)
            self.db.set_setting("telegram_chat_id", self.chat_id)
            self.after(0, self._sync_telegram_chat_id_ui)
            self.after(0, self._refresh_dashboard_metrics)

        command = text.split()[0].split("@")[0].lower()
        if command in ("/start", "/id"):
            response = (
                "AutoSOC AI is connected.\n"
                f"Telegram User ID: {user_id}\n"
                f"Telegram Chat ID: {chat_id}\n\n"
                "Notifications use the Chat ID.\n"
                "You can now return to the app and press Save & Test."
            )
            self.telegram_client.send_message(chat_id, response, parse_mode=None)
        elif command == "/help":
            help_text = (
                "Available commands:\n"
                "/start - connect this chat\n"
                "/id - show your current IDs\n"
                "/help - show this help"
            )
            self.telegram_client.send_message(chat_id, help_text, parse_mode=None)

    def _sync_telegram_chat_id_ui(self):
        self.tg_entry.delete(0, "end")
        self.tg_entry.insert(0, self.chat_id)
        self.tg_status.configure(
            text=f"Chat ID captured from Telegram.\nActive chat_id: {self.chat_id}",
            text_color="#7fe3b1",
        )

    def _looks_like_chat_id(self, value):
        if not value:
            return False
        if value.startswith("-"):
            return value[1:].isdigit()
        return value.isdigit()

    def toggle_port(self, port, switch_obj):
        is_open = bool(switch_obj.get())
        action = "allow" if is_open else "block"
        rule_name = f"AutoSOC_Manual_{port}"
        os.system(f'netsh advfirewall firewall delete rule name="{rule_name}"')
        os.system(
            f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action={action} protocol=TCP localport={port}'
        )
        service = self.port_definitions.get(port, "Unknown")
        state_text = "ALLOWED" if is_open else "BLOCKED"
        self.result_box.insert(
            "0.0",
            f"[FIREWALL] Port {port} ({service}) {state_text}\n",
            "success" if is_open else "danger",
        )

    def update_threshold(self, value):
        self.guard.threshold = int(value)
        self.slider_label.configure(text=f"DDoS Sensitivity: {int(value)}")

    def toggle_guard(self):
        if not self.guard.is_monitoring:
            self.guard.start_monitoring()
            self.btn_guard.configure(text="AI Guard: Active", fg_color="#1f805d", hover_color="#166446")
            self.status_label.configure(text="AI GUARD ACTIVE", text_color="#6bf0a7")
        else:
            self.guard.stop()
            self.btn_guard.configure(text="AI Guard: Off", fg_color="#243244", hover_color="#31445b")
            self.status_label.configure(text="SYSTEM READY", text_color="#6bf0a7")

    def on_threat_detected(self, ip, reason, cmd):
        alert_ui = f"\n[THREAT] Suspicious activity from {ip}\n[ACTION] Blocked automatically.\n"
        self.after(0, lambda: self.result_box.insert("0.0", alert_ui, "danger"))

        alert_tg = (
            f"🚨 *AutoSOC AI Threat Detected*\n\n"
            f"IP: `{ip}`\n"
            f"Reason: {reason}\n"
            f"Action: Automatically blocked"
        )
        threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()

    def animate_ai_fab(self):
        if not hasattr(self, "ai_fab"):
            return
        self.ai_fab_animation_tick += 1
        y_offset = int(math.sin(self.ai_fab_animation_tick / 10) * 8)
        self.ai_fab.place_configure(x=-34, y=-38 - y_offset)
        palette = ["#77beff", "#8fc8ff", "#9bd0ff", "#8fc8ff"]
        color = palette[(self.ai_fab_animation_tick // 8) % len(palette)]
        self.ai_fab.configure(fg_color=color)
        self.after(90, self.animate_ai_fab)

    def open_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists():
            self.ai_chat_window.deiconify()
            self.ai_chat_window.lift()
            self.ai_chat_window.focus()
            return

        self.ai_chat_window = ctk.CTkToplevel(self)
        self.ai_chat_window.title("AutoSOC AI Chat")
        self.ai_chat_window.geometry("470x650")
        self.ai_chat_window.configure(fg_color="#0a1522")
        self.ai_chat_window.attributes("-topmost", True)
        self.ai_chat_window.protocol("WM_DELETE_WINDOW", self.close_ai_chat_window)

        ctk.CTkLabel(
            self.ai_chat_window,
            text="AutoSOC AI Chat",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=18, pady=(18, 6))

        ctk.CTkLabel(
            self.ai_chat_window,
            text="Security copiloting with Azerbaijani context awareness and guided remediation",
            text_color="#87a5c0",
            font=ctk.CTkFont(size=12),
            wraplength=410,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 10))

        popup_faq = ctk.CTkScrollableFrame(self.ai_chat_window, fg_color="#0d1b2a", corner_radius=16, height=110)
        popup_faq.pack(fill="x", padx=18, pady=(0, 10))
        for question in self.FAQ_ITEMS:
            ctk.CTkButton(
                popup_faq,
                text=question,
                height=32,
                corner_radius=10,
                fg_color="#142433",
                hover_color="#1d3348",
                command=lambda q=question: self.ask_ai_assistant(q),
            ).pack(fill="x", padx=6, pady=4)

        popup_chat = ctk.CTkTextbox(
            self.ai_chat_window,
            fg_color="#08111b",
            corner_radius=16,
            border_width=1,
            border_color="#1d3347",
            text_color="#dce8f2",
            font=ctk.CTkFont(size=12),
        )
        popup_chat.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        popup_chat.insert("end", self.assistant_output.get("0.0", "end").strip())
        self.popup_chat_box = popup_chat

        self.popup_loader = ctk.CTkLabel(
            self.ai_chat_window,
            text="",
            text_color="#8fbfff",
            font=ctk.CTkFont(size=11),
        )
        self.popup_loader.pack(anchor="w", padx=18, pady=(0, 6))

        bottom = ctk.CTkFrame(self.ai_chat_window, fg_color="transparent")
        bottom.pack(fill="x", padx=18, pady=(0, 18))
        bottom.grid_columnconfigure(0, weight=1)

        self.popup_entry = ctk.CTkEntry(
            bottom,
            height=42,
            corner_radius=14,
            placeholder_text="Ask about a port, a threat, or tell me to take action",
            fg_color="#101b28",
            border_color="#2c445b",
        )
        self.popup_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.popup_entry.bind("<Return>", lambda e: self.ask_ai_assistant())

        self.popup_send = ctk.CTkButton(
            bottom,
            text="Send",
            width=90,
            height=42,
            corner_radius=14,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            command=self.ask_ai_assistant,
        )
        self.popup_send.grid(row=0, column=1, sticky="e")

    def close_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists():
            self.ai_chat_window.withdraw()

    def start_scan_thread(self):
        target = self.ip_entry.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Please enter an IP address or hostname.")
            return
        self.btn_scan.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="SCAN IN PROGRESS", text_color="#ffd36b")
        self.result_box.delete("0.0", "end")
        threading.Thread(target=self.run_logic, args=(target,), daemon=True).start()

    def ask_ai_assistant(self, preset_question=None):
        question = (preset_question or self._get_active_question() or "").strip()
        if not question:
            return

        self._set_active_question("")
        self._append_chat_message("You", question)
        self._set_chat_controls_state("disabled")

        immediate_action = self._handle_actionable_request(question)
        if immediate_action:
            self._finish_ai_request(immediate_action)
            return

        self.start_ai_loader()
        threading.Thread(target=self._run_ai_request, args=(question,), daemon=True).start()

    def _get_active_question(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_entry"):
            popup_text = self.popup_entry.get().strip()
            if popup_text:
                return popup_text
        return self.assistant_entry.get().strip()

    def _set_active_question(self, value):
        self.assistant_entry.delete(0, "end")
        if value:
            self.assistant_entry.insert(0, value)
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_entry"):
            self.popup_entry.delete(0, "end")
            if value:
                self.popup_entry.insert(0, value)

    def _set_chat_controls_state(self, state):
        self.assistant_button.configure(state=state)
        self.assistant_entry.configure(state=state)
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_send"):
            self.popup_send.configure(state=state)
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_entry"):
            self.popup_entry.configure(state=state)

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

        if port and any(marker in lowered for marker in close_markers):
            switch = self.switches.get(port)
            if switch and switch.get():
                switch.deselect()
                self.toggle_port(port, switch)
            service = self.port_definitions.get(port, "service")
            return f"I blocked port {port} ({service}) in the Windows firewall and reduced the attack surface."

        if port and any(marker in lowered for marker in open_markers):
            switch = self.switches.get(port)
            if switch and not switch.get():
                switch.select()
                self.toggle_port(port, switch)
            service = self.port_definitions.get(port, "service")
            return f"I allowed port {port} ({service}) in the Windows firewall."

        if self.last_scan_data and any(marker in lowered for marker in secure_markers + ["şübhəli portları bağla", "close suspicious ports", "закрой опасные порты"]):
            risks = self._collect_risks(self.last_scan_data)
            blocked_ports = []
            for risk in risks:
                risk_port = risk["port"]
                switch = self.switches.get(risk_port)
                if switch and switch.get():
                    switch.deselect()
                    self.toggle_port(risk_port, switch)
                    blocked_ports.append(str(risk_port))
            if blocked_ports:
                return f"I proactively blocked the risky ports detected in the last scan: {', '.join(blocked_ports)}."
            return "I reviewed the last scan, but there were no currently open risky ports left to block."

        return None

    def _run_ai_request(self, question):
        answer = self.ai_expert.answer_question(question, self.last_scan_data)
        self.after(0, lambda: self._finish_ai_request(answer))

    def _finish_ai_request(self, answer):
        self.stop_ai_loader()
        self._append_chat_message("AutoSOC AI", answer)
        self.assistant_summary.delete("0.0", "end")
        self.assistant_summary.insert("end", answer)
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_chat_box"):
            self.popup_chat_box.delete("0.0", "end")
            self.popup_chat_box.insert("end", self.assistant_output.get("0.0", "end").strip())
        self._set_chat_controls_state("normal")

    def start_ai_loader(self):
        self.ai_loader_step = 0
        self._tick_ai_loader()

    def _tick_ai_loader(self):
        dots = "." * ((self.ai_loader_step % 3) + 1)
        loading_text = f"Analyzing{dots}"
        self.assistant_loader.configure(text=loading_text)
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_loader"):
            self.popup_loader.configure(text=loading_text)
        self.ai_loader_step += 1
        self.ai_loader_job = self.after(350, self._tick_ai_loader)

    def stop_ai_loader(self):
        if self.ai_loader_job:
            self.after_cancel(self.ai_loader_job)
            self.ai_loader_job = None
        self.assistant_loader.configure(text="")
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and hasattr(self, "popup_loader"):
            self.popup_loader.configure(text="")

    def run_logic(self, target):
        try:
            scanner = NetworkScanner()
            analyzer = RiskAnalyzer()
            data = scanner.scan_network(target, ports=list(self.port_definitions.keys()))
            self.last_scan_data = data

            self.result_box.insert("end", f">>> SCANNING TARGET: {target}\n", "ai")
            total_risks = 0

            for device in data:
                vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Unknown device"
                ip = device.get("ip", "unknown")
                self.result_box.insert("end", f"\n[DEVICE] {vendor} ({ip})\n", "info")

                open_ports = device.get("ports", [])
                if open_ports:
                    ports_view = ", ".join(
                        f"{item['port']} ({self.port_definitions.get(int(item['port']), item.get('name', 'Unknown'))})"
                        for item in open_ports
                    )
                    self.result_box.insert("end", f"    Open Ports: {ports_view}\n", "info")
                else:
                    self.result_box.insert("end", "    No open tracked services detected\n", "success")

                risks = analyzer.analyze(open_ports)
                for risk in risks:
                    port = risk["port"]
                    service = risk["info"]["service"]
                    if port in self.switches and not self.switches[port].get():
                        self.result_box.insert("end", f"    Port {port}: already isolated by firewall\n", "ai")
                        continue

                    total_risks += 1
                    self.result_box.insert("end", f"    Risk: Port {port} ({service})\n", "danger")
                    instruction = self.ai_expert.generate_instruction(vendor, port, service, "az")
                    self.result_box.insert("end", f"    AI: {instruction}\n", "ai")

            risk_score = min(total_risks * 25, 100)
            self.scan_summary = self.ai_expert.summarize_scan(data, "az")
            self.assistant_summary.delete("0.0", "end")
            self.assistant_summary.insert("end", self.scan_summary)
            self._refresh_dashboard_metrics()

            if total_risks > 0:
                alert_tg = (
                    f"🔍 *AutoSOC AI Scan Result*\n\n"
                    f"Target: `{target}`\n"
                    f"Detected threats: *{total_risks}*\n"
                    f"Risk score: *{risk_score}%*"
                )
                threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()
            else:
                self.result_box.insert("end", "\nNo critical issues detected.\n", "success")

            self.db.add_scan(target, risk_score, f"{total_risks} problem(s)")
        except Exception as exc:
            self.result_box.insert("end", f"\n[ERROR] {exc}\n", "danger")
        finally:
            self.btn_scan.configure(state="normal", text="Network Scan")
            self.status_label.configure(text="SYSTEM READY", text_color="#6bf0a7")
            self._refresh_dashboard_metrics()

    def show_history(self):
        win = ctk.CTkToplevel(self)
        win.title("Audit Journal")
        win.geometry("760x500")
        win.configure(fg_color="#0a1522")
        win.attributes("-topmost", True)

        ctk.CTkLabel(
            win,
            text="Audit Journal",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(20, 8))

        txt = ctk.CTkTextbox(
            win,
            fg_color="#08111b",
            corner_radius=16,
            text_color="#dce8f2",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        txt.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        for row in self.db.get_all_scans():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]}% | {row[3]}\n")


if __name__ == "__main__":
    import login

    def on_login_success(user):
        app = AutoSOCApp()
        app.title(f"AutoSOC AI: Cyber Shield v3.0  |  {user['username']} ({user['role']})")
        app.mainloop()

    login.launch(on_login_success)
