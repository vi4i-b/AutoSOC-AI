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

        self._build_ports_card(default_wraplength)
        self._build_telegram_card(default_wraplength)

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
            text="Inspect suspicious URLs, preview site content, and review risk signals",
            font=ctk.CTkFont(size=13),
            text_color="#85a3bd",
        ).pack(anchor="w", pady=(4, 0))

        body = ctk.CTkFrame(self.new_tab_frame, fg_color=theme.BG_SIDEBAR, corner_radius=22)
        body.grid(row=2, column=0, sticky="nsew", padx=26, pady=(0, 26))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=6)
        body.grid_rowconfigure(2, weight=3)

        url_bar = ctk.CTkFrame(body, fg_color="transparent")
        url_bar.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 12))
        url_bar.grid_columnconfigure(0, weight=1)

        self.phishing_url_entry = ctk.CTkEntry(
            url_bar,
            height=46,
            corner_radius=14,
            placeholder_text="https://example.com",
            fg_color=theme.BG_CONSOLE,
            border_color="#2c445b",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=14),
        )
        self.phishing_url_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.btn_phishing_analyze = ctk.CTkButton(
            url_bar,
            text="Analyze",
            width=138,
            height=46,
            corner_radius=14,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.btn_phishing_analyze.grid(row=0, column=1, sticky="e", padx=(0, 10))

        self.btn_phishing_ai = ctk.CTkButton(
            url_bar,
            text="AI",
            width=56,
            height=46,
            corner_radius=14,
            fg_color="#112033",
            hover_color="#19324d",
            border_width=1,
            border_color="#315274",
            text_color=theme.ACCENT_CYAN,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.btn_phishing_ai.grid(row=0, column=2, sticky="e")

        browser_card = ctk.CTkFrame(body, fg_color=theme.BG_PANEL, corner_radius=18)
        browser_card.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))
        browser_card.grid_columnconfigure(0, weight=1)
        browser_card.grid_rowconfigure(1, weight=1)

        browser_header = ctk.CTkFrame(browser_card, fg_color="transparent")
        browser_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        browser_header.grid_columnconfigure(1, weight=1)

        dot_row = ctk.CTkFrame(browser_header, fg_color="transparent")
        dot_row.grid(row=0, column=0, sticky="w")
        for color in (theme.ACCENT_RED, theme.ACCENT_YELLOW, theme.ACCENT_GREEN):
            ctk.CTkLabel(
                dot_row,
                text="●",
                text_color=color,
                font=ctk.CTkFont(size=13),
            ).pack(side="left", padx=(0, 5))

        ctk.CTkLabel(
            browser_header,
            text="Preview sandbox",
            text_color="#85a3bd",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).grid(row=0, column=1, sticky="w", padx=10)

        ctk.CTkLabel(
            browser_header,
            text="Not connected",
            text_color=theme.ACCENT_YELLOW,
            font=ctk.CTkFont(size=12, weight="bold"),
        ).grid(row=0, column=2, sticky="e")

        preview = ctk.CTkFrame(browser_card, fg_color=theme.BG_CONSOLE, corner_radius=16,
                               border_width=1, border_color="#1f3449")
        preview.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        preview.grid_columnconfigure(0, weight=1)
        preview.grid_rowconfigure(0, weight=1)

        preview_stack = ctk.CTkFrame(preview, fg_color="transparent")
        preview_stack.grid(row=0, column=0)

        ctk.CTkLabel(
            preview_stack,
            text="Website preview",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack()
        ctk.CTkLabel(
            preview_stack,
            text="The embedded browser surface will render the submitted URL here.",
            text_color="#85a3bd",
            font=ctk.CTkFont(size=13),
        ).pack(pady=(8, 0))

        analysis_card = ctk.CTkFrame(body, fg_color=theme.BG_PANEL, corner_radius=18)
        analysis_card.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        analysis_card.grid_columnconfigure(0, weight=3)
        analysis_card.grid_columnconfigure(1, weight=2)
        analysis_card.grid_rowconfigure(0, weight=1)

        findings = ctk.CTkFrame(analysis_card, fg_color=theme.BG_CONSOLE, corner_radius=16,
                                border_width=1, border_color="#1f3449")
        findings.grid(row=0, column=0, sticky="nsew", padx=(16, 10), pady=16)
        findings.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            findings,
            text="Site Risk Analysis",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=17, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        signals = [
            ("Domain reputation", "No known blocklist hits in the current design state.", theme.ACCENT_GREEN),
            ("Login form behavior", "Form collection points will be inspected after backend integration.", theme.ACCENT_YELLOW),
            ("Certificate check", "TLS and issuer details will appear here.", theme.ACCENT_CYAN),
            ("Content indicators", "Brand impersonation, urgency language, and redirects will be scored.", "#ff9f6e"),
        ]
        for row, (label, detail, color) in enumerate(signals, start=1):
            signal = ctk.CTkFrame(findings, fg_color="transparent")
            signal.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 8))
            ctk.CTkLabel(signal, text="●", text_color=color, font=ctk.CTkFont(size=14)).pack(side="left", padx=(0, 8))
            text_stack = ctk.CTkFrame(signal, fg_color="transparent")
            text_stack.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(
                text_stack,
                text=label,
                text_color=theme.TEXT_SOFT,
                font=ctk.CTkFont(size=12, weight="bold"),
            ).pack(anchor="w")
            ctk.CTkLabel(
                text_stack,
                text=detail,
                text_color="#85a3bd",
                font=ctk.CTkFont(size=11),
                wraplength=520,
                justify="left",
            ).pack(anchor="w")

        score_card = ctk.CTkFrame(analysis_card, fg_color=theme.BG_CONSOLE, corner_radius=16,
                                  border_width=1, border_color="#1f3449")
        score_card.grid(row=0, column=1, sticky="nsew", padx=(10, 16), pady=16)
        score_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            score_card,
            text="Safety Score",
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=17, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        ctk.CTkLabel(
            score_card,
            text="64%",
            text_color=theme.ACCENT_YELLOW,
            font=ctk.CTkFont(size=48, weight="bold"),
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 0))

        ctk.CTkLabel(
            score_card,
            text="Moderate confidence",
            text_color="#85a3bd",
            font=ctk.CTkFont(size=12),
        ).grid(row=2, column=0, sticky="w", padx=16, pady=(0, 12))

        score_bar = ctk.CTkProgressBar(
            score_card,
            height=14,
            corner_radius=8,
            fg_color="#142433",
            progress_color=theme.ACCENT_YELLOW,
        )
        score_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 14))
        score_bar.set(0.64)

        ctk.CTkLabel(
            score_card,
            text="Verdict",
            text_color=theme.TEXT_SOFT,
            font=ctk.CTkFont(size=12, weight="bold"),
        ).grid(row=4, column=0, sticky="w", padx=16, pady=(4, 4))

        ctk.CTkLabel(
            score_card,
            text=(
                "The site is not marked dangerous yet, but several checks are pending. "
                "Treat the URL as suspicious until analysis completes."
            ),
            text_color="#9fb4c8",
            font=ctk.CTkFont(size=12),
            wraplength=300,
            justify="left",
        ).grid(row=5, column=0, sticky="nw", padx=16, pady=(0, 16))

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
