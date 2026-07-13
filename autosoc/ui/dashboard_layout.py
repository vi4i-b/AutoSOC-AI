"""Widget construction for the dashboard window.

:class:`DashboardLayoutMixin` builds every widget of the main window and owns
zero business logic — command callbacks live in
:class:`autosoc.ui.dashboard.AutoSOCApp`, which mixes this class in. Keeping
construction separate keeps both files readable.
"""

import tkinter as tk
import webbrowser

import customtkinter as ctk

from autosoc.ui import theme


class DashboardLayoutMixin:
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, fg_color=theme.BG_SIDEBAR, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        default_wraplength = 300

        self.sidebar_scroll = ctk.CTkScrollableFrame(
            self.sidebar,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color="#23384d",
            scrollbar_button_hover_color=theme.ACCENT_BLUE,
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
            wraplength=default_wraplength,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 18))

        control_card = ctk.CTkFrame(self.sidebar_scroll, fg_color=theme.BG_CARD, corner_radius=18)
        control_card.pack(fill="x", padx=22, pady=(0, 16))

        self.btn_scan = ctk.CTkButton(
            control_card,
            text="Network Scan",
            height=48,
            corner_radius=14,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.start_scan_thread,
        )
        self.btn_scan.pack(fill="x", padx=16, pady=(16, 10))

        self.btn_guard = ctk.CTkButton(
            control_card,
            text="Guard: Off",
            height=46,
            corner_radius=14,
            fg_color=theme.BTN_NEUTRAL,
            hover_color=theme.BTN_NEUTRAL_HOVER,
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
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color=theme.BTN_OUTLINE_BORDER,
            command=self.show_history,
        )
        self.btn_history.pack(fill="x", padx=16, pady=(0, 16))

        sensitivity_card = ctk.CTkFrame(self.sidebar_scroll, fg_color=theme.BG_CARD, corner_radius=18)
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
            progress_color=theme.ACCENT_BLUE,
            button_color="#b5d0ff",
            button_hover_color="#dce9ff",
        )
        self.threshold_slider.pack(fill="x", padx=16, pady=(0, 12))
        self.threshold_slider.set(500)

        ctk.CTkLabel(
            sensitivity_card,
            text="Lower values react faster. Higher values reduce false positives.",
            text_color=theme.TEXT_FAINT,
            font=ctk.CTkFont(size=11),
            wraplength=default_wraplength,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 16))

        prevention_card = ctk.CTkFrame(self.sidebar_scroll, fg_color=theme.BG_CARD, corner_radius=18)
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
            fg_color=theme.ACCENT_RED_DARK,
            hover_color=theme.ACCENT_RED_DARK_HOVER,
            command=self.harden_risky_ports,
        )
        self.btn_harden.pack(side="left", padx=(0, 6))

        self.btn_canary = ctk.CTkButton(
            prevention_row,
            text="Port Canary: Off",
            width=165,
            height=34,
            corner_radius=12,
            fg_color=theme.BTN_NEUTRAL,
            hover_color=theme.BTN_NEUTRAL_HOVER,
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
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color=theme.BTN_OUTLINE_BORDER,
            command=self.run_port_canary_self_test,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            prevention_row_two,
            text="Event Feed",
            width=165,
            height=32,
            corner_radius=12,
            fg_color="transparent",
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color=theme.BTN_OUTLINE_BORDER,
            command=self.show_event_feed,
        ).pack(side="left")

        self.prevention_status = ctk.CTkLabel(
            prevention_card,
            text="Canary idle. Risky-port hardening is ready.",
            text_color=theme.TEXT_FAINT,
            font=ctk.CTkFont(size=11),
            wraplength=default_wraplength,
            justify="left",
        )
        self.prevention_status.pack(anchor="w", padx=16, pady=(0, 16))

        self._build_ai_engine_card(default_wraplength)
        self._build_ports_card(default_wraplength)
        self._build_telegram_card(default_wraplength)

    def _build_ai_engine_card(self, default_wraplength):
        card = ctk.CTkFrame(self.sidebar_scroll, fg_color=theme.BG_CARD, corner_radius=18)
        card.pack(fill="x", padx=22, pady=(0, 16))

        ctk.CTkLabel(
            card,
            text="AI Engine (NVIDIA)",
            text_color="#e8f1f8",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(16, 6))

        ctk.CTkLabel(
            card,
            text="Paste your NVIDIA API key to power the security copilot and AI phishing verdicts.",
            text_color=theme.TEXT_FAINT,
            font=ctk.CTkFont(size=11),
            wraplength=default_wraplength,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 8))

        self.nvidia_key_entry = ctk.CTkEntry(
            card,
            height=38,
            corner_radius=12,
            placeholder_text="nvapi-...",
            show="•",
            fg_color=theme.BG_FIELD,
            border_color=theme.FIELD_BORDER,
        )
        self.nvidia_key_entry.pack(fill="x", padx=16, pady=(0, 8))
        if getattr(self, "nvidia_api_key", ""):
            self.nvidia_key_entry.insert(0, self.nvidia_api_key)

        self.nvidia_model_entry = ctk.CTkEntry(
            card,
            height=38,
            corner_radius=12,
            placeholder_text="Model (e.g. deepseek-ai/deepseek-v3)",
            fg_color=theme.BG_FIELD,
            border_color=theme.FIELD_BORDER,
        )
        self.nvidia_model_entry.pack(fill="x", padx=16, pady=(0, 8))
        if getattr(self, "nvidia_model", ""):
            self.nvidia_model_entry.insert(0, self.nvidia_model)

        key_btn_row = ctk.CTkFrame(card, fg_color="transparent")
        key_btn_row.pack(fill="x", padx=16, pady=(0, 8))

        self.btn_show_key = ctk.CTkButton(
            key_btn_row,
            text="Show",
            width=70,
            height=34,
            corner_radius=12,
            fg_color="transparent",
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color=theme.BTN_OUTLINE_BORDER,
            command=self.toggle_nvidia_key_visibility,
        )
        self.btn_show_key.pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            key_btn_row,
            text="Save & Apply",
            height=34,
            corner_radius=12,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            command=self.save_nvidia_key,
        ).pack(side="left", fill="x", expand=True)

        self.nvidia_key_status = ctk.CTkLabel(
            card,
            text="",
            text_color=theme.TEXT_FAINT,
            font=ctk.CTkFont(size=11),
            wraplength=default_wraplength,
            justify="left",
        )
        self.nvidia_key_status.pack(anchor="w", padx=16, pady=(0, 8))
        self._refresh_nvidia_key_status()

        ctk.CTkButton(
            card,
            text="Open SOC Console",
            height=38,
            corner_radius=12,
            fg_color="#243a2f",
            hover_color="#2c4a3a",
            border_width=1,
            border_color="#2f6f52",
            text_color="#9ce0bd",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.open_soc_console,
        ).pack(fill="x", padx=16, pady=(0, 16))

    def _build_ports_card(self, default_wraplength):
        ports_card = ctk.CTkFrame(self.sidebar_scroll, fg_color=theme.BG_CARD, corner_radius=18)
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
            fg_color=theme.ACCENT_GREEN_DARK,
            hover_color=theme.ACCENT_GREEN_DARK_HOVER,
            command=self.enable_all_ports,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            actions_row,
            text="Block All",
            width=150,
            height=34,
            corner_radius=12,
            fg_color=theme.ACCENT_RED_DARK,
            hover_color=theme.ACCENT_RED_DARK_HOVER,
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
        ports_y_scroll.pack(fill="y", padx=(6, 8), pady=8)
        self.ports_canvas.configure(yscrollcommand=ports_y_scroll.set)

        self.ports_frame = ctk.CTkFrame(self.ports_canvas, fg_color="#0c1623", corner_radius=0)
        self.ports_canvas_window = self.ports_canvas.create_window((0, 0), window=self.ports_frame, anchor="nw")

        for port, service in sorted(self.port_definitions.items()):
            switch = ctk.CTkSwitch(
                self.ports_frame,
                text=f"Port {port}  •  {service}",
                progress_color=theme.ACCENT_BLUE,
                button_color="#d2e3ff",
                button_hover_color="#f3f8ff",
                command=lambda p=port: self.toggle_port(p, self.switches[p]),
            )
            switch.pack(anchor="w", padx=10, pady=4)
            switch.deselect()
            self.switches[port] = switch

        self.ports_canvas.configure(scrollregion=self.ports_canvas.bbox("all"))
        self._bind_ports_scrolling()

    def _bind_ports_scrolling(self):
        """Route the mouse wheel to the ports list while the cursor is over it."""
        parent_scroll_func = self.sidebar_scroll._mouse_wheel_all

        def scroll_only_ports(event):
            # Linux reports Button-4/5; Windows reports <MouseWheel> delta.
            if event.num == 4 or event.delta > 0:
                self.ports_canvas.yview_scroll(-1, "units")
            elif event.num == 5 or event.delta < 0:
                self.ports_canvas.yview_scroll(1, "units")

        def on_enter_ports(_event):
            self.sidebar_scroll.unbind_all("<MouseWheel>")
            self.sidebar_scroll.unbind_all("<Button-4>")
            self.sidebar_scroll.unbind_all("<Button-5>")

            self.ports_canvas.bind_all("<MouseWheel>", scroll_only_ports)
            self.ports_canvas.bind_all("<Button-4>", scroll_only_ports)
            self.ports_canvas.bind_all("<Button-5>", scroll_only_ports)

        def on_leave_ports(_event):
            self.ports_canvas.unbind_all("<MouseWheel>")
            self.ports_canvas.unbind_all("<Button-4>")
            self.ports_canvas.unbind_all("<Button-5>")

            self.sidebar_scroll.bind_all("<MouseWheel>", parent_scroll_func)
            self.sidebar_scroll.bind_all("<Button-4>", parent_scroll_func)
            self.sidebar_scroll.bind_all("<Button-5>", parent_scroll_func)

        self.ports_canvas.bind("<Enter>", on_enter_ports)
        self.ports_canvas.bind("<Leave>", on_leave_ports)

        self.ports_canvas.bind("<Configure>", lambda e: self.ports_canvas.itemconfig(
            self.ports_canvas_window, width=e.width))
        self.ports_frame.bind("<Configure>", lambda e: self.ports_canvas.configure(
            scrollregion=self.ports_canvas.bbox("all")))

    def _build_telegram_card(self, default_wraplength):
        telegram_card = ctk.CTkFrame(self.sidebar_scroll, fg_color=theme.BG_CARD, corner_radius=18)
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
            fg_color=theme.BG_FIELD,
            border_color=theme.FIELD_BORDER,
        )
        self.tg_entry.pack(fill="x", padx=16, pady=(0, 8))
        if self.chat_id:
            self.tg_entry.insert(0, self.chat_id)

        self.tg_status = ctk.CTkLabel(
            telegram_card,
            text="Waiting for Telegram configuration",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=11),
            justify="left",
            wraplength=default_wraplength,
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
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
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
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color=theme.BTN_OUTLINE_BORDER,
            command=lambda: webbrowser.open(self.telegram_bot_url),
        ).pack(side="left")

        self.btn_resync_tg = ctk.CTkButton(
            telegram_card,
            text="Resync /start Listener",
            height=34,
            corner_radius=12,
            fg_color=theme.BTN_NEUTRAL,
            hover_color=theme.BTN_NEUTRAL_HOVER,
            command=self.restart_telegram_listener,
        )
        self.btn_resync_tg.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkLabel(
            telegram_card,
            text="Write /start to the bot. The app will capture the Chat ID and use it for notifications.",
            text_color=theme.TEXT_FAINT,
            font=ctk.CTkFont(size=11),
            wraplength=default_wraplength,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 16))

    def _show_page(self, page):
        if not hasattr(self, "main_frame") or not hasattr(self, "new_tab_frame"):
            return

        if page == "new_tab":
            self.main_frame.grid_remove()
            self.new_tab_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
            self._set_section_nav_state("new_tab")
            return

        self.new_tab_frame.grid_remove()
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
        self._set_section_nav_state("dashboard")

    def _build_section_nav(self, parent):
        nav = ctk.CTkFrame(parent, fg_color="#0c1724", corner_radius=14)
        nav.grid(row=0, column=0, sticky="ew", padx=26, pady=(18, 10))
        nav.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(
            nav,
            text="Section",
            text_color="#85a3bd",
            font=ctk.CTkFont(size=11, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=(14, 10), pady=10)

        dashboard_btn = ctk.CTkButton(
            nav,
            text="Dashboard",
            width=138,
            height=34,
            corner_radius=10,
            fg_color="transparent",
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color="#263d55",
            text_color="#9fb4c8",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self._show_page("dashboard"),
        )
        dashboard_btn.grid(row=0, column=1, sticky="w", padx=(0, 8), pady=10)

        phishing_btn = ctk.CTkButton(
            nav,
            text="Anti-Phishing Analysis",
            width=210,
            height=34,
            corner_radius=10,
            fg_color="transparent",
            hover_color=theme.BTN_OUTLINE_HOVER,
            border_width=1,
            border_color="#263d55",
            text_color="#9fb4c8",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self._show_page("new_tab"),
        )
        phishing_btn.grid(row=0, column=2, sticky="w", pady=10)

        return dashboard_btn, phishing_btn

    def _set_section_nav_state(self, active_page):
        active = {
            "fg_color": "#132842",
            "hover_color": "#193958",
            "border_width": 1,
            "border_color": "#3d6ea1",
            "text_color": "#dce8f2",
        }
        inactive = {
            "fg_color": "transparent",
            "hover_color": theme.BTN_OUTLINE_HOVER,
            "border_width": 1,
            "border_color": "#263d55",
            "text_color": "#9fb4c8",
        }

        for button in getattr(self, "dashboard_nav_buttons", []):
            button.configure(**(active if active_page == "dashboard" else inactive))
        for button in getattr(self, "phishing_nav_buttons", []):
            button.configure(**(active if active_page == "new_tab" else inactive))

    def _build_main_panel(self):
        self.main_frame = ctk.CTkFrame(self, fg_color=theme.BG_DEEP, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
        self.main_frame.grid_rowconfigure(3, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.dashboard_nav_buttons = []
        self.phishing_nav_buttons = []
        dashboard_btn, phishing_btn = self._build_section_nav(self.main_frame)
        self.dashboard_nav_buttons.append(dashboard_btn)
        self.phishing_nav_buttons.append(phishing_btn)

        self.topbar = ctk.CTkFrame(self.main_frame, fg_color=theme.BG_DEEP, corner_radius=0)
        self.topbar.grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 14))
        self.topbar.grid_columnconfigure(0, weight=1)

        title_block = ctk.CTkFrame(self.topbar, fg_color="transparent")
        title_block.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            title_block,
            text="Security Operations Dashboard",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color=theme.TEXT_PRIMARY,
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
        self.ip_entry.insert(0, self.default_scan_target)

        ctk.CTkButton(
            actions,
            text="Start Scan",
            width=130,
            height=44,
            corner_radius=14,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            command=self.start_scan_thread,
        ).pack(side="left")

        metrics = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        metrics.grid(row=2, column=0, sticky="ew", padx=26, pady=(0, 14))
        for idx in range(5):
            metrics.grid_columnconfigure(idx, weight=1)

        self.metric_total_devices = self._metric_card(metrics, 0, "Devices", "0", "#4cc9f0")
        self.metric_open_ports = self._metric_card(metrics, 1, "Open Ports", "0", theme.ACCENT_GREEN)
        self.metric_risk = self._metric_card(metrics, 2, "Risk Score", "0%", "#ff9f6e")
        self.metric_incidents = self._metric_card(metrics, 3, "Incidents", "0", theme.ACCENT_YELLOW)
        self.metric_tg = self._metric_card(metrics, 4, "Telegram", "Offline", theme.ACCENT_RED)

        content = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        content.grid(row=3, column=0, sticky="nsew", padx=26, pady=(0, 26))
        content.grid_columnconfigure(0, weight=7)
        content.grid_columnconfigure(1, weight=5)
        content.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(content, fg_color=theme.BG_SIDEBAR, corner_radius=22)
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
            text_color=theme.STATUS_OK,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.status_label.grid(row=0, column=1, sticky="e")

        self.result_box = ctk.CTkTextbox(
            left,
            fg_color=theme.BG_DEEP,
            corner_radius=18,
            border_color="#1f3449",
            border_width=1,
            text_color="#dbe8f4",
            font=ctk.CTkFont(family="Consolas", size=13),
        )
        self.result_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.result_box.tag_config("danger", foreground=theme.STATUS_DANGER)
        self.result_box.tag_config("success", foreground="#66e0a3")
        self.result_box.tag_config("ai", foreground=theme.ACCENT_CYAN)
        self.result_box.tag_config("info", foreground=theme.ACCENT_YELLOW)
        self.result_box.tag_config("muted", foreground="#8ca3b8")

        right = ctk.CTkFrame(content, fg_color=theme.BG_SIDEBAR, corner_radius=22)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)
        right.grid_columnconfigure(0, weight=1)

        summary_card = ctk.CTkFrame(right, fg_color=theme.BG_PANEL, corner_radius=18)
        summary_card.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 12))

        ctk.CTkLabel(
            summary_card,
            text="Situation Brief",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(14, 8))

        self.assistant_summary = ctk.CTkTextbox(
            summary_card,
            height=130,
            fg_color=theme.BG_CONSOLE,
            corner_radius=16,
            text_color="#d8e6f3",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.assistant_summary.pack(fill="x", padx=16, pady=(0, 14))

        faq_card = ctk.CTkFrame(right, fg_color=theme.BG_PANEL, corner_radius=18)
        faq_card.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 12))

        ctk.CTkLabel(
            faq_card,
            text="Smart Prompts",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(14, 10))

        self.faq_buttons_frame = ctk.CTkFrame(faq_card, fg_color="transparent")
        self.faq_buttons_frame.pack(fill="x", padx=12, pady=(0, 12))
        self._build_faq_buttons(self.faq_buttons_frame)

        chat_card = ctk.CTkFrame(right, fg_color=theme.BG_PANEL, corner_radius=18)
        chat_card.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        chat_card.grid_rowconfigure(1, weight=1)
        chat_card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(chat_card, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Security Copilot (NVIDIA)",
            text_color=theme.TEXT_PRIMARY,
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
            fg_color=theme.BG_CONSOLE,
            corner_radius=16,
            border_color="#1d3347",
            border_width=1,
            text_color=theme.TEXT_SOFT,
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
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            command=self.ask_ai_assistant,
        )
        self.assistant_button.grid(row=0, column=1, sticky="e")

    def _build_new_tab_panel(self):
        self.new_tab_frame = ctk.CTkFrame(self, fg_color=theme.BG_DEEP, corner_radius=0)
        self.new_tab_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
        self.new_tab_frame.grid_columnconfigure(0, weight=1)
        self.new_tab_frame.grid_rowconfigure(2, weight=1)

        dashboard_btn, phishing_btn = self._build_section_nav(self.new_tab_frame)
        self.dashboard_nav_buttons.append(dashboard_btn)
        self.phishing_nav_buttons.append(phishing_btn)

        header = ctk.CTkFrame(self.new_tab_frame, fg_color="transparent")
        header.grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 14))

        ctk.CTkLabel(
            header,
            text="Anti-Phishing Analysis",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color=theme.TEXT_PRIMARY,
        ).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="Analyze a URL: structure, TLS certificate, page content, spelling, and an AI verdict",
            font=ctk.CTkFont(size=13),
            text_color="#85a3bd",
        ).pack(anchor="w", pady=(4, 0))

        body = ctk.CTkFrame(self.new_tab_frame, fg_color=theme.BG_SIDEBAR, corner_radius=22)
        body.grid(row=2, column=0, sticky="nsew", padx=26, pady=(0, 26))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        # ── URL bar ──────────────────────────────────────────────────
        url_bar = ctk.CTkFrame(body, fg_color="transparent")
        url_bar.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 12))
        url_bar.grid_columnconfigure(0, weight=1)

        self.phishing_url_entry = ctk.CTkEntry(
            url_bar,
            height=46,
            corner_radius=14,
            placeholder_text="https://example.com/login",
            fg_color=theme.BG_CONSOLE,
            border_color="#2c445b",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=14),
        )
        self.phishing_url_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.phishing_url_entry.bind("<Return>", lambda e: self.analyze_phishing_url(deep=True))

        self.btn_phishing_quick = ctk.CTkButton(
            url_bar,
            text="Quick Check",
            width=120,
            height=46,
            corner_radius=14,
            fg_color=theme.BTN_NEUTRAL,
            hover_color=theme.BTN_NEUTRAL_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self.analyze_phishing_url(deep=False),
        )
        self.btn_phishing_quick.grid(row=0, column=1, sticky="e", padx=(0, 8))

        self.btn_phishing_analyze = ctk.CTkButton(
            url_bar,
            text="Full Analyze",
            width=138,
            height=46,
            corner_radius=14,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.analyze_phishing_url(deep=True),
        )
        self.btn_phishing_analyze.grid(row=0, column=2, sticky="e", padx=(0, 8))

        self.phishing_status = ctk.CTkLabel(
            body,
            text="Enter a URL and run Quick Check (offline heuristics) or Full Analyze (fetches the page, TLS, spelling, AI).",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
        )
        self.phishing_status.grid(row=0, column=0, sticky="ew", padx=18, pady=(70, 0))

        # ── Result area: left signals list, right verdict/score ──────
        result_area = ctk.CTkFrame(body, fg_color="transparent")
        result_area.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        result_area.grid_columnconfigure(0, weight=3)
        result_area.grid_columnconfigure(1, weight=2)
        result_area.grid_rowconfigure(0, weight=1)

        # Signals (scrollable)
        signals_card = ctk.CTkFrame(result_area, fg_color=theme.BG_PANEL, corner_radius=18)
        signals_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        signals_card.grid_columnconfigure(0, weight=1)
        signals_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            signals_card,
            text="Detection Signals",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.phishing_signals_frame = ctk.CTkScrollableFrame(
            signals_card,
            fg_color=theme.BG_CONSOLE,
            corner_radius=14,
            scrollbar_button_color="#23384d",
            scrollbar_button_hover_color=theme.ACCENT_BLUE,
        )
        self.phishing_signals_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        self.phishing_signals_frame.grid_columnconfigure(0, weight=1)

        self._phishing_placeholder = ctk.CTkLabel(
            self.phishing_signals_frame,
            text="No analysis yet. Results will appear here.",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=12),
        )
        self._phishing_placeholder.grid(row=0, column=0, sticky="w", padx=12, pady=12)

        # Verdict / score
        score_card = ctk.CTkFrame(result_area, fg_color=theme.BG_PANEL, corner_radius=18)
        score_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        score_card.grid_columnconfigure(0, weight=1)
        score_card.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(
            score_card,
            text="Risk Score",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        self.phishing_score_label = ctk.CTkLabel(
            score_card,
            text="—",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=48, weight="bold"),
        )
        self.phishing_score_label.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 0))

        self.phishing_verdict_label = ctk.CTkLabel(
            score_card,
            text="Awaiting analysis",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.phishing_verdict_label.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 10))

        self.phishing_score_bar = ctk.CTkProgressBar(
            score_card,
            height=14,
            corner_radius=8,
            fg_color="#142433",
            progress_color=theme.BTN_NEUTRAL,
        )
        self.phishing_score_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 14))
        self.phishing_score_bar.set(0)

        self.phishing_verdict_detail = ctk.CTkLabel(
            score_card,
            text="Run an analysis to see the verdict and a breakdown of contributing signals.",
            text_color="#9fb4c8",
            font=ctk.CTkFont(size=12),
            wraplength=280,
            justify="left",
        )
        self.phishing_verdict_detail.grid(row=4, column=0, sticky="nw", padx=16, pady=(0, 12))

        self.phishing_ai_box = ctk.CTkTextbox(
            score_card,
            height=150,
            fg_color=theme.BG_CONSOLE,
            corner_radius=14,
            text_color=theme.TEXT_SOFT,
            font=ctk.CTkFont(size=12),
            wrap="word",
        )
        self.phishing_ai_box.grid(row=5, column=0, sticky="nsew", padx=16, pady=(0, 12))
        self.phishing_ai_box.insert("end", "AI verdict will appear here when a NVIDIA model key is configured (left panel).")
        self.phishing_ai_box.configure(state="disabled")

        self.btn_phishing_to_case = ctk.CTkButton(
            score_card,
            text="Send to SOC Cases",
            height=38,
            corner_radius=12,
            fg_color=theme.ACCENT_RED_DARK,
            hover_color=theme.ACCENT_RED_DARK_HOVER,
            state="disabled",
            command=self.send_phishing_to_case,
        )
        self.btn_phishing_to_case.grid(row=6, column=0, sticky="ew", padx=16, pady=(0, 16))

    def _metric_card(self, parent, column, label, value, accent):
        card = ctk.CTkFrame(parent, fg_color=theme.BG_SIDEBAR, corner_radius=20)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0 if column == 4 else 8))
        ctk.CTkLabel(
            card,
            text=label,
            text_color=theme.TEXT_MUTED,
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
                text_color=theme.TEXT_SOFT,
                font=ctk.CTkFont(size=11),
                command=lambda q=question: self.ask_ai_assistant(q),
            )
            button.grid(row=row, column=col, sticky="ew", padx=4, pady=4)
