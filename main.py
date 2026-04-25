import ipaddress
import json
import math
import os
import queue
import socket
import subprocess
import threading
import time
import webbrowser

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox

from ai_expert import AISecurityExpert
from analyzer import RiskAnalyzer
from auth import get_user_telegram, update_user_telegram
from canary import PortCanary
from database import SOCDatabase
from guard import NetworkGuard
from log_listener import WindowsLogListener
from nvidia_ai import NvidiaSecurityAI
from runtime_support import TelegramBotClient, apply_window_icon, load_env_file, resource_path
from scanner import NetworkScanner
from validators import is_safe_scan_target, looks_like_chat_id

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class AutoSOCApp(ctk.CTk):
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
        saved_chat_id = self.db.get_setting("telegram_chat_id", "").strip()
        latest_tg_user = self.db.get_latest_telegram_user()
        user_tg = get_user_telegram(self.current_user.get("username", "")) if self.current_user.get("username") else None
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = (
            (user_tg or {}).get("telegram_chat_id", "").strip()
            or self.current_user.get("telegram_chat_id", "").strip()
            or saved_chat_id
            or os.getenv("TELEGRAM_CHAT_ID", "").strip()
        )
        if not self.chat_id and latest_tg_user:
            self.chat_id = str(latest_tg_user[1])

        self.telegram_bot_url = os.getenv("TELEGRAM_BOT_URL", "https://t.me/AutoSOC_Baku_Bot").strip()
        self.telegram_client = TelegramBotClient(self.bot_token)
        self.telegram_listener_running = False
        self.telegram_listener_healthy = False
        self.telegram_bot_online = False
        self.telegram_offset = None
        self.bot_identity = None

        self.ai_expert = AISecurityExpert()
        self.nvidia_ai = NvidiaSecurityAI()
        self.analyzer = RiskAnalyzer()
        self.guard = NetworkGuard(self.on_threat_detected)
        self.port_canary = PortCanary(self.on_canary_trip)
        self.last_scan_data = []
        self.scan_summary = ""
        self.ai_chat_window = None
        self.ai_bubble_hint = None
        self.ai_badge = None
        self.ai_fab_icon = None
        self.ai_loader_job = None
        self.ai_loader_step = 0
        self.ai_fab_animation_tick = 0
        self.chat_history = []
        self.incident_count = 0
        self.previous_scan_snapshot = self._load_exposure_baseline()
        self.latest_new_exposures = []
        self.ui_queue = queue.Queue()
        self.log_listener = None
        self.log_listener_warning_shown = False

        self.title("AutoSOC: Cyber Shield v3.0")
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
        self._refresh_prevention_status()
        self._check_telegram_status()
        self.after(120, self._drain_ui_queue)
        self.start_windows_log_listener()

        if self.telegram_client.enabled:
            self.start_telegram_listener()

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

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=390, fg_color="#0b1623", corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar_scroll = ctk.CTkScrollableFrame(
            self.sidebar,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color="#23384d",
            scrollbar_button_hover_color="#2b7fff",
        )
        self.sidebar_scroll.pack(fill="both", expand=True)

        brand = ctk.CTkFrame(self.sidebar_scroll, fg_color="#0f2033", corner_radius=20)
        brand.pack(fill="x", padx=22, pady=(22, 16))
        ctk.CTkLabel(
            brand,
            text="AutoSOC",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#f2f7fb",
        ).pack(anchor="w", padx=18, pady=(18, 2))
        ctk.CTkLabel(
            brand,
            text="SOC cockpit for network visibility, response, and Telegram alerting",
            font=ctk.CTkFont(size=12),
            text_color="#8ea8bf",
            wraplength=310,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 18))

        control_card = ctk.CTkFrame(self.sidebar_scroll, fg_color="#101c2b", corner_radius=18)
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
            text="Guard: Off",
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

        sensitivity_card = ctk.CTkFrame(self.sidebar_scroll, fg_color="#101c2b", corner_radius=18)
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
            wraplength=310,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 16))

        prevention_card = ctk.CTkFrame(self.sidebar_scroll, fg_color="#101c2b", corner_radius=18)
        prevention_card.pack(fill="x", padx=22, pady=(0, 16))

        ctk.CTkLabel(
            prevention_card,
            text="Prevention Toolkit",
            text_color="#e8f1f8",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(16, 8))

        prevention_row = ctk.CTkFrame(prevention_card, fg_color="transparent")
        prevention_row.pack(fill="x", padx=16, pady=(0, 8))

        self.btn_harden = ctk.CTkButton(
            prevention_row,
            text="Harden Risky",
            width=150,
            height=34,
            corner_radius=12,
            fg_color="#88344d",
            hover_color="#6d263c",
            command=self.harden_risky_ports,
        )
        self.btn_harden.pack(side="left", padx=(0, 6))

        self.btn_canary = ctk.CTkButton(
            prevention_row,
            text="Port Canary: Off",
            width=165,
            height=34,
            corner_radius=12,
            fg_color="#243244",
            hover_color="#31445b",
            command=self.toggle_port_canary,
        )
        self.btn_canary.pack(side="left")

        prevention_row_two = ctk.CTkFrame(prevention_card, fg_color="transparent")
        prevention_row_two.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkButton(
            prevention_row_two,
            text="Self-Test",
            width=150,
            height=32,
            corner_radius=12,
            fg_color="transparent",
            hover_color="#172433",
            border_width=1,
            border_color="#2b425a",
            command=self.run_port_canary_self_test,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            prevention_row_two,
            text="Event Feed",
            width=165,
            height=32,
            corner_radius=12,
            fg_color="transparent",
            hover_color="#172433",
            border_width=1,
            border_color="#2b425a",
            command=self.show_event_feed,
        ).pack(side="left")

        self.prevention_status = ctk.CTkLabel(
            prevention_card,
            text="Canary idle. Risky-port hardening is ready.",
            text_color="#7f95ab",
            font=ctk.CTkFont(size=11),
            wraplength=310,
            justify="left",
        )
        self.prevention_status.pack(anchor="w", padx=16, pady=(0, 16))

        ports_card = ctk.CTkFrame(self.sidebar_scroll, fg_color="#101c2b", corner_radius=18)
        ports_card.pack(fill="x", padx=22, pady=(0, 16))

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
            width=150,
            height=34,
            corner_radius=12,
            fg_color="#1f805d",
            hover_color="#166446",
            command=self.enable_all_ports,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            actions_row,
            text="Block All",
            width=150,
            height=34,
            corner_radius=12,
            fg_color="#88344d",
            hover_color="#6d263c",
            command=self.disable_all_ports,
        ).pack(side="left")

        ports_scroll_shell = ctk.CTkFrame(ports_card, fg_color="#0c1623", corner_radius=14)
        ports_scroll_shell.pack(fill="both", expand=True, padx=16, pady=(0, 10))

        self.ports_canvas = tk.Canvas(
            ports_scroll_shell,
            bg="#0c1623",
            bd=0,
            highlightthickness=0,
            xscrollincrement=18,
            yscrollincrement=18,
        )
        self.ports_canvas.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)

        ports_y_scroll = ctk.CTkScrollbar(
            ports_scroll_shell,
            orientation="vertical",
            command=self.ports_canvas.yview,
        )
        ports_y_scroll.pack(side="right", fill="y", padx=(6, 8), pady=8)
        self.ports_canvas.configure(yscrollcommand=ports_y_scroll.set)

        self.ports_frame = ctk.CTkFrame(self.ports_canvas, fg_color="#0c1623", corner_radius=0)
        self.ports_canvas_window = self.ports_canvas.create_window((0, 0), window=self.ports_frame, anchor="nw")

        def sync_port_scrollregion(_event=None):
            self.ports_canvas.configure(scrollregion=self.ports_canvas.bbox("all"))

        self.ports_frame.bind("<Configure>", sync_port_scrollregion)

        for port, service in sorted(self.port_definitions.items()):
            switch = ctk.CTkSwitch(
                self.ports_frame,
                width=470,
                text=f"Port {port}  •  {service}",
                progress_color="#2b7fff",
                button_color="#d2e3ff",
                button_hover_color="#f3f8ff",
                command=lambda p=port: self.toggle_port(p, self.switches[p]),
            )
            switch.pack(anchor="w", padx=10, pady=4)
            switch.select()
            self.switches[port] = switch

        self.ports_canvas.configure(scrollregion=self.ports_canvas.bbox("all"))

        ports_x_scroll = ctk.CTkScrollbar(
            ports_card,
            orientation="horizontal",
            command=self.ports_canvas.xview,
        )
        ports_x_scroll.pack(fill="x", padx=16, pady=(0, 16))
        self.ports_canvas.configure(xscrollcommand=ports_x_scroll.set)

        telegram_card = ctk.CTkFrame(self.sidebar_scroll, fg_color="#101c2b", corner_radius=18)
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
            wraplength=310,
        )
        self.tg_status.pack(anchor="w", padx=16, pady=(0, 10))

        btn_row = ctk.CTkFrame(telegram_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 8))

        self.btn_save_tg = ctk.CTkButton(
            btn_row,
            text="Save & Test",
            width=145,
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
            width=145,
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
            wraplength=310,
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
        for idx in range(5):
            metrics.grid_columnconfigure(idx, weight=1)

        self.metric_total_devices = self._metric_card(metrics, 0, "Devices", "0", "#4cc9f0")
        self.metric_open_ports = self._metric_card(metrics, 1, "Open Ports", "0", "#5dd39e")
        self.metric_risk = self._metric_card(metrics, 2, "Risk Score", "0%", "#ff9f6e")
        self.metric_incidents = self._metric_card(metrics, 3, "Incidents", "0", "#ffd36b")
        self.metric_tg = self._metric_card(metrics, 4, "Telegram", "Offline", "#ff6b7a")

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
            text="Situation Brief",
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
            text="Security Copilot (NVIDIA)",
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
        icon_path = resource_path("assets", "app_icon.png")
        try:
            base_icon = tk.PhotoImage(file=icon_path)
            self.ai_fab_icon = base_icon.subsample(10, 10)
        except tk.TclError:
            self.ai_fab_icon = None

        self.ai_fab = ctk.CTkButton(
            self,
            text="",
            image=self.ai_fab_icon,
            width=54,
            height=54,
            corner_radius=27,
            fg_color="#0f1d2c",
            hover_color="#17304b",
            border_width=1,
            border_color="#294661",
            border_spacing=0,
            command=self.toggle_ai_chat_window,
        )
        self.ai_fab.place(relx=1.0, rely=1.0, x=-22, y=-20, anchor="se")

        self.bind("<Configure>", lambda _event: self._position_ai_chat_window())

    def _position_ai_chat_window(self):
        if not (self.ai_chat_window and self.ai_chat_window.winfo_exists()):
            return

        self.update_idletasks()
        root_x = self.winfo_rootx()
        root_y = self.winfo_rooty()
        width = self.winfo_width()
        height = self.winfo_height()

        panel_width = 430
        panel_height = 620
        pos_x = root_x + width - panel_width - 28
        pos_y = root_y + height - panel_height - 108
        self.ai_chat_window.geometry(f"{panel_width}x{panel_height}+{pos_x}+{pos_y}")

    def _sync_ai_bubble_state(self):
        chat_open = bool(self.ai_chat_window and self.ai_chat_window.winfo_exists() and self.ai_chat_window.state() != "withdrawn")
        if hasattr(self, "ai_fab"):
            if chat_open:
                self.ai_fab.configure(fg_color="#1b3550", hover_color="#234364", border_color="#6fa8e2")
            else:
                self.ai_fab.configure(fg_color="#0f1d2c", hover_color="#17304b", border_color="#294661")

    def _metric_card(self, parent, column, label, value, accent):
        card = ctk.CTkFrame(parent, fg_color="#0b1623", corner_radius=20)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0 if column == 4 else 8))
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
        open_ports = self._count_live_open_ports()
        findings = self._collect_risks(self.last_scan_data)
        active_findings = []
        for finding in findings:
            switch = self.switches.get(finding["port"])
            if switch and not switch.get():
                continue
            active_findings.append(finding)
        risk_score = self.analyzer.calculate_risk_score(active_findings)

        self.metric_total_devices.configure(text=str(total_devices))
        self.metric_open_ports.configure(text=str(open_ports))
        self.metric_risk.configure(text=f"{risk_score}%")
        self.metric_incidents.configure(text=str(self.incident_count))

        if self.telegram_bot_online and self.chat_id and self.telegram_listener_healthy:
            self.metric_tg.configure(text="Ready", text_color="#6de0a8")
        elif self.telegram_bot_online and self.chat_id:
            self.metric_tg.configure(text="Bot Online", text_color="#7fe3b1")
        elif self.telegram_bot_online:
            self.metric_tg.configure(text="No Chat ID", text_color="#ffd36b")
        else:
            self.metric_tg.configure(text="Offline", text_color="#ff7c85")

    def _count_live_open_ports(self):
        if self.switches:
            return sum(1 for switch in self.switches.values() if switch.get())
        return 0

    def _count_live_detected_risks(self):
        if not self.last_scan_data:
            return 0

        risk_count = 0
        for risk in self._collect_risks(self.last_scan_data):
            port = risk["port"]
            switch = self.switches.get(port)
            if switch and not switch.get():
                continue
            risk_count += 1
        return risk_count

    def _check_telegram_status(self):
        if not self.telegram_client.enabled:
            self.telegram_bot_online = False
            self.telegram_listener_healthy = False
            self.tg_status.configure(
                text="Telegram bot token tapılmadı. .env faylında TELEGRAM_BOT_TOKEN əlavə edin.",
                text_color="#ff8a8a",
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
            self.tg_status.configure(text=text, text_color="#7fe3b1")
        else:
            self.telegram_bot_online = False
            self.telegram_listener_healthy = False
            self.tg_status.configure(
                text=f"Telegram xətası: {data.get('description', 'unknown error')}",
                text_color="#ff8a8a",
            )
        self._refresh_dashboard_metrics()

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
            self.btn_canary.configure(text="Port Canary: On", fg_color="#1f805d", hover_color="#166446")
        else:
            canary_text = "Canary idle. Risky-port hardening is ready."
            self.btn_canary.configure(text="Port Canary: Off", fg_color="#243244", hover_color="#31445b")

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

    def enable_all_ports(self):
        for port, switch in self.switches.items():
            if not switch.get():
                switch.select()
                self.toggle_port(port, switch)
        self.result_box.insert("0.0", "[FIREWALL] All tracked ports allowed\n", "success")
        self._refresh_dashboard_metrics()

    def disable_all_ports(self):
        for port, switch in self.switches.items():
            if switch.get():
                switch.deselect()
                self.toggle_port(port, switch)
        self.result_box.insert("0.0", "[FIREWALL] All tracked ports blocked\n", "danger")
        self._refresh_dashboard_metrics()

    def save_telegram_id(self):
        new_id = self.tg_entry.get().strip()
        if not new_id:
            self.tg_status.configure(text="Chat ID is empty.", text_color="#ff8a8a")
            return
        if not looks_like_chat_id(new_id):
            self.tg_status.configure(text="Chat ID format looks invalid.", text_color="#ff8a8a")
            return

        self.chat_id = new_id
        if self.current_user.get("username"):
            if not update_user_telegram(self.current_user["username"], self.chat_id):
                self.tg_status.configure(text="This Telegram Chat ID is already linked to another account.", text_color="#ff8a8a")
                return
            self.current_user["telegram_chat_id"] = self.chat_id
        self.db.set_setting("telegram_chat_id", self.chat_id)
        self.db.add_audit_event(
            "telegram_binding_requested",
            self.current_user.get("username", "local_operator"),
            f"Telegram Chat ID set to {self.chat_id}.",
        )
        self.tg_status.configure(text="Testing Telegram connection...", text_color="#ffd36b")
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
                text_color="#7fe3b1",
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
                text_color="#ff8a8a",
            ))

    def send_telegram_alert(self, message_text):
        if not self.chat_id:
            return
        final_message = message_text
        if self.scan_summary and "*AI advice:*" not in final_message:
            final_message = f"{message_text}\n\n*AI advice:*\n{self.scan_summary}"
        ok, data = self.telegram_client.send_message(self.chat_id, final_message)
        if not ok:
            self._ui(lambda: self.result_box.insert(
                "0.0",
                f"[TELEGRAM ERROR] {data.get('description', 'unknown error')}\n",
                "danger",
            ))

    def start_telegram_listener(self):
        if self.telegram_listener_running or not self.telegram_client.enabled:
            return
        self.telegram_listener_running = True
        self.telegram_listener_healthy = False
        self._refresh_dashboard_metrics()
        threading.Thread(target=self._telegram_polling_loop, daemon=True).start()

    def restart_telegram_listener(self):
        self.telegram_listener_running = False
        self.telegram_listener_healthy = False
        self.after(1200, self.start_telegram_listener)
        self.tg_status.configure(text="Telegram listener restarting...", text_color="#ffd36b")
        self._refresh_dashboard_metrics()

    def start_windows_log_listener(self):
        if self.log_listener:
            return

        self.log_listener = WindowsLogListener(
            on_detection=self.on_windows_bruteforce_detected,
            on_error=self.on_windows_log_listener_error,
            event_id=4625,
            threshold=5,
            window_seconds=10,
            poll_interval=1.0,
        )

        if self.log_listener.start():
            return

        if os.name == "nt" and not self.log_listener_warning_shown:
            self.log_listener_warning_shown = True
            self._append_result(
                "[WARN] Windows Security log listener unavailable. Install pywin32 to enable Event ID 4625 monitoring.\n",
                "info",
                index="0.0",
            )

    def on_windows_log_listener_error(self, message):
        if self.log_listener_warning_shown:
            return
        self.log_listener_warning_shown = True
        self._append_result(f"[WARN] {message}\n", "info", index="0.0")

    def on_windows_bruteforce_detected(self, detection):
        source_ip = detection.get("ip", "unknown")
        attempt_count = detection.get("attempt_count", 0)
        window_seconds = detection.get("window_seconds", 10)
        service_name = detection.get("service", "Windows Logon")
        details = (
            f"Detected {attempt_count} failed Windows logon events (Event ID 4625) "
            f"from {source_ip} within {window_seconds} seconds."
        )

        self.incident_count += 1
        self.db.add_security_event("windows_bruteforce", "Critical", source_ip, details)
        self._append_result(f"[CRITICAL] {service_name} brute-force detected from {source_ip}!\n", "danger", index="0.0")
        self._set_status("WINDOWS BRUTE-FORCE DETECTED", "#ff7c85")
        self._ui(self._refresh_dashboard_metrics)

    def _telegram_polling_loop(self):
        while self.telegram_client.enabled and self.telegram_listener_running:
            ok, data = self.telegram_client.get_updates(offset=self.telegram_offset, timeout=20)
            if not ok:
                self.telegram_listener_healthy = False
                description = data.get("description", "unknown error")
                self._ui(lambda d=description: self.tg_status.configure(
                    text=f"Telegram listener error: {d}",
                    text_color="#ff8a8a",
                ))
                self._ui(self._refresh_dashboard_metrics)
                time.sleep(4)
                continue

            if not self.telegram_listener_healthy:
                self.telegram_listener_healthy = True
                self._ui(self._refresh_dashboard_metrics)

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
            if self.current_user.get("username"):
                if update_user_telegram(self.current_user["username"], self.chat_id, str(user_id)):
                    self.current_user["telegram_chat_id"] = self.chat_id
                    self.current_user["telegram_user_id"] = str(user_id)
            self.db.set_setting("telegram_chat_id", self.chat_id)
            self._ui(self._sync_telegram_chat_id_ui)
            self._ui(self._refresh_dashboard_metrics)

        if not text:
            return

        normalized = text.lower()
        command = normalized.split()[0].split("@")[0]
        if command in ("/start", "/id"):
            response = (
                "AutoSOC is connected.\n"
                f"Telegram User ID: {user_id}\n"
                f"Telegram Chat ID: {chat_id}\n\n"
                "Use the Telegram Chat ID during registration in the app.\n"
                "After login, scan alerts and port information will be sent to this chat."
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
            text_color="#7fe3b1",
        )

    def toggle_port_canary(self):
        if not self.port_canary.is_running:
            status = self.port_canary.start()
            if status["bound_ports"]:
                self.result_box.insert(
                    "0.0",
                    f"[CANARY] Listening on decoy ports: {', '.join(str(port) for port in status['bound_ports'])}\n",
                    "ai",
                )
                self.status_label.configure(text="PORT CANARY ACTIVE", text_color="#7fe3b1")
            else:
                self.result_box.insert("0.0", "[CANARY] Failed to bind decoy ports\n", "danger")
        else:
            self.port_canary.stop()
            self.result_box.insert("0.0", "[CANARY] Decoy listeners stopped\n", "muted")
            self.status_label.configure(text="SYSTEM READY", text_color="#6bf0a7")

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

    def harden_risky_ports(self):
        if self.last_scan_data:
            risky_ports = [item["port"] for item in self._collect_risks(self.last_scan_data)]
        else:
            risky_ports = [21, 23, 445, 3389, 5900, 6379, 27017, 3306, 1433, 1521]

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
            blocked, rule_name, block_result = self._block_ip_in_firewall(ip, rule_prefix="AutoSOC_Canary_Block")
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
        self._set_status("PORT CANARY ALERT", "#ff8a8a" if not is_local else "#ffd36b")
        self._ui(self._refresh_dashboard_metrics)
        self._ui(self._refresh_prevention_status)

        if self.chat_id:
            alert = (
                f"🚨 *AutoSOC Port Canary*\n\n"
                f"Source: `{source}`\n"
                f"Decoy port: `{port}`\n"
                f"Severity: *{severity}*\n"
                f"Action: *{'logged only (local test)' if is_local else 'firewall block attempted'}*"
            )
            threading.Thread(target=self.send_telegram_alert, args=(alert,), daemon=True).start()

    def show_event_feed(self):
        win = ctk.CTkToplevel(self)
        win.title("Event Feed")
        win.geometry("860x520")
        win.configure(fg_color="#0a1522")
        win.attributes("-topmost", True)

        ctk.CTkLabel(
            win,
            text="Security Event Feed",
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

        for row in self.db.get_recent_security_events():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}\n")

    def toggle_port(self, port, switch_obj):
        is_open = bool(switch_obj.get())
        service = self.port_definitions.get(port, "Unknown")
        success, rule_name, firewall_message = self._set_port_firewall_rule(port, is_open)
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
        self._refresh_dashboard_metrics()

    def update_threshold(self, value):
        self.guard.threshold = int(value)
        self.slider_label.configure(text=f"DDoS Sensitivity: {int(value)}")

    def toggle_guard(self):
        if not self.guard.is_monitoring:
            self.guard.start_monitoring()
            self.btn_guard.configure(text="Guard: Active", fg_color="#1f805d", hover_color="#166446")
            self.status_label.configure(text="GUARD ACTIVE", text_color="#6bf0a7")
        else:
            self.guard.stop()
            self.btn_guard.configure(text="Guard: Off", fg_color="#243244", hover_color="#31445b")
            self.status_label.configure(text="SYSTEM READY", text_color="#6bf0a7")

    def _run_netsh(self, arguments):
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            return subprocess.run(
                ["netsh", *arguments],
                capture_output=True,
                text=True,
                check=False,
                creationflags=creation_flags,
            )
        except OSError as exc:
            class _NetshErrorResult:
                def __init__(self, message):
                    self.returncode = 1
                    self.stdout = ""
                    self.stderr = str(message)

            return _NetshErrorResult(exc)

    def _set_port_firewall_rule(self, port, allow_traffic):
        rule_name = f"AutoSOC_Manual_{int(port)}"
        action = "allow" if allow_traffic else "block"
        self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
        result = self._run_netsh(
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                f"action={action}",
                "protocol=TCP",
                f"localport={int(port)}",
            ]
        )
        combined_output = " ".join(
            part.strip()
            for part in (getattr(result, "stdout", ""), getattr(result, "stderr", ""))
            if part and part.strip()
        )
        if result.returncode == 0:
            return True, rule_name, combined_output or "Firewall rule updated successfully."
        return False, rule_name, combined_output or f"netsh exited with code {result.returncode}."

    def _block_ip_in_firewall(self, ip, rule_prefix="AutoSOC_Guard_Block"):
        try:
            normalized_ip = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return False, "", f"Invalid IP address: {ip}"

        rule_name = f"{rule_prefix}_{normalized_ip}"
        self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
        add_result = self._run_netsh(
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={normalized_ip}",
            ]
        )

        combined_output = " ".join(
            part.strip()
            for part in (add_result.stdout, add_result.stderr)
            if part and part.strip()
        )
        if add_result.returncode == 0:
            return True, rule_name, combined_output or "Firewall rule added successfully."
        return False, rule_name, combined_output or f"netsh exited with code {add_result.returncode}."

    def on_threat_detected(self, ip, reason, cmd):
        self.incident_count += 1
        blocked, rule_name, block_message = self._block_ip_in_firewall(ip)
        action_text = "Blocked automatically." if blocked else "Automatic block failed. Manual action required."
        self.db.add_security_event(
            "traffic_spike",
            "High",
            ip,
            f"{reason}. Firewall rule: {rule_name or 'n/a'}. Result: {block_message}. Suggested command: {cmd}",
        )
        alert_ui = f"\n[THREAT] Suspicious activity from {ip}\n[ACTION] {action_text}\n"
        if not blocked:
            alert_ui += f"[DETAIL] {block_message}\n"
        self._ui(lambda: self.result_box.insert("0.0", alert_ui, "danger"))
        self._set_status("GUARD BLOCKED THREAT" if blocked else "GUARD ALERT", "#ff8a8a")
        self._ui(self._refresh_dashboard_metrics)
        self._ui(self._refresh_prevention_status)

        alert_tg = (
            f"🚨 *AutoSOC Threat Detected*\n\n"
            f"IP: `{ip}`\n"
            f"Reason: {reason}\n"
            f"Action: {'Automatically blocked' if blocked else 'Automatic block failed'}"
        )
        if not blocked:
            alert_tg += f"\nDetails: {block_message}"
        threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()

    def animate_ai_fab(self):
        return

    def toggle_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists() and self.ai_chat_window.state() != "withdrawn":
            self.close_ai_chat_window()
            return
        self.open_ai_chat_window()

    def open_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists():
            self.ai_chat_window.deiconify()
            self.ai_chat_window.lift()
            self.ai_chat_window.focus()
            self._position_ai_chat_window()
            self._sync_ai_bubble_state()
            return

        self.ai_chat_window = ctk.CTkToplevel(self)
        self.ai_chat_window.title("AutoSOC Chat")
        self.ai_chat_window.geometry("430x620")
        self.ai_chat_window.configure(fg_color="#0a1522")
        self.ai_chat_window.attributes("-topmost", True)
        self.ai_chat_window.protocol("WM_DELETE_WINDOW", self.close_ai_chat_window)
        self.ai_chat_window.resizable(False, False)
        self._position_ai_chat_window()

        popup_header = ctk.CTkFrame(self.ai_chat_window, fg_color="#0d1b2a", corner_radius=18)
        popup_header.pack(fill="x", padx=14, pady=(14, 10))
        popup_header.grid_columnconfigure(0, weight=1)

        title_stack = ctk.CTkFrame(popup_header, fg_color="transparent")
        title_stack.grid(row=0, column=0, sticky="w", padx=14, pady=12)

        ctk.CTkLabel(
            title_stack,
            text="AutoSOC AI Assistant",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_stack,
            text="Floating security copilot with NVIDIA-powered replies",
            text_color="#87a5c0",
            font=ctk.CTkFont(size=12),
            wraplength=300,
            justify="left",
        ).pack(anchor="w", pady=(3, 0))

        ctk.CTkButton(
            popup_header,
            text="×",
            width=38,
            height=38,
            corner_radius=19,
            fg_color="#142433",
            hover_color="#1d3348",
            text_color="#dce8f2",
            font=ctk.CTkFont(size=18, weight="bold"),
            command=self.close_ai_chat_window,
        ).grid(row=0, column=1, sticky="e", padx=12, pady=12)

        popup_faq = ctk.CTkScrollableFrame(self.ai_chat_window, fg_color="#0d1b2a", corner_radius=16, height=100)
        popup_faq.pack(fill="x", padx=14, pady=(0, 10))
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
        popup_chat.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        popup_chat.insert("end", self.assistant_output.get("0.0", "end").strip())
        self.popup_chat_box = popup_chat

        self.popup_loader = ctk.CTkLabel(
            self.ai_chat_window,
            text="",
            text_color="#8fbfff",
            font=ctk.CTkFont(size=11),
        )
        self.popup_loader.pack(anchor="w", padx=16, pady=(0, 6))

        bottom = ctk.CTkFrame(self.ai_chat_window, fg_color="transparent")
        bottom.pack(fill="x", padx=14, pady=(0, 14))
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
            text="Ask",
            width=90,
            height=42,
            corner_radius=14,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            command=self.ask_ai_assistant,
        )
        self.popup_send.grid(row=0, column=1, sticky="e")
        self._sync_ai_bubble_state()

    def close_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists():
            self.ai_chat_window.withdraw()
        self._sync_ai_bubble_state()

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
        self.status_label.configure(text="SCAN IN PROGRESS", text_color="#ffd36b")
        self.result_box.delete("0.0", "end")
        self.assistant_summary.delete("0.0", "end")
        self.assistant_summary.insert("end", "Scan in progress. Metrics will refresh as devices are processed.")
        self._refresh_dashboard_metrics()
        self.db.add_audit_event("scan_started", self.current_user.get("username", "local_operator"), f"Target: {target}")
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
            return f"I blocked port {port} ({service}) in the Windows firewall and reduced the attack surface."

        if port and any(marker in lowered for marker in open_markers):
            switch = self.switches.get(port)
            if switch and not switch.get():
                switch.select()
                self.toggle_port(port, switch)
            service = self.port_definitions.get(port, "service")
            return f"I allowed port {port} ({service}) in the Windows firewall."

        if self.last_scan_data and any(marker in lowered for marker in secure_markers + ["şübhəli portları bağla", "close suspicious ports", "закрой опасные порты"]):
            self.harden_risky_ports()
            return "I applied the risky-port hardening routine based on the current scan context."

        return None

    def _run_ai_request(self, question):
        history = self._build_nvidia_chat_history()[:-1]
        answer = self.nvidia_ai.answer_security_question(question, self.last_scan_data, history=history)
        if not answer:
            answer = self.ai_expert.answer_question(question, self.last_scan_data)
        self._ui(lambda: self._finish_ai_request(answer))

    def _finish_ai_request(self, answer):
        self.stop_ai_loader()
        self._append_chat_message("AutoSOC", answer)
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
            data = scanner.scan_network(target, ports=list(self.port_definitions.keys()))
            processed_devices = []

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
                        self._append_result(f"    Port {port}: already isolated by firewall\n", "ai")
                        continue

                    total_risks += 1
                    severity = risk["info"]["risk"]
                    self._append_result(f"    Risk: Port {port} ({service}) [{severity}]\n", "danger")
                    instruction = self.ai_expert.generate_instruction(vendor, port, service, "az")
                    self._append_result(f"    Guidance: {instruction}\n", "ai")
                    self._ui(self._refresh_dashboard_metrics)

            findings = self._collect_risks(data)
            risk_score = self.analyzer.calculate_risk_score(findings)
            self.scan_summary = self.nvidia_ai.analyze_ports(target, data) or self.ai_expert.summarize_scan(data, "ru")
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
                    f"Target: `{target}`\n"
                    f"Detected threats: *{total_risks}*\n"
                    f"Risk score: *{risk_score}%*\n\n"
                    f"*Open ports by device:*\n{telegram_ports_text}"
                )
                threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()
            else:
                self._append_result("\nNo critical issues detected.\n", "success")
                alert_tg = (
                    f"✅ *AutoSOC Scan Result*\n\n"
                    f"Target: `{target}`\n"
                    f"Detected threats: *0*\n"
                    f"Risk score: *0%*\n\n"
                    f"*Open ports by device:*\n{telegram_ports_text}"
                )
                threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()

            self.db.add_scan(target, risk_score, f"{total_risks} problem(s)")
            self.db.add_audit_event(
                "scan_completed",
                self.current_user.get("username", "local_operator"),
                f"Target: {target}. Risk score: {risk_score}. Threats: {total_risks}.",
            )
        except Exception as exc:
            self._append_result(f"\n[ERROR] {exc}\n", "danger")
            self.db.add_audit_event(
                "scan_failed",
                self.current_user.get("username", "local_operator"),
                f"Target: {target}. Error: {exc}",
            )
        finally:
            self._ui(lambda: self.btn_scan.configure(state="normal", text="Network Scan"))
            self._set_status("SYSTEM READY", "#6bf0a7")
            self._ui(self._refresh_dashboard_metrics)

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
        txt.insert("end", "\n--- Security Events ---\n")
        for row in self.db.get_recent_security_events():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}\n")
        txt.insert("end", "\n--- Audit Events ---\n")
        for row in self.db.get_recent_audit_events():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]} | {row[3]}\n")


if __name__ == "__main__":
    import login

    def on_login_success(user):
        app = AutoSOCApp(current_user=user)
        app.title(f"AutoSOC: Cyber Shield v3.0  |  {user['username']} ({user['role']})")
        app.mainloop()

    login.launch(on_login_success)
