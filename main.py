import customtkinter as ctk
import threading
import socket
import telebot
import os
import json
from tkinter import messagebox

# Импорт твоих модулей
from scanner import NetworkScanner
from analyzer import RiskAnalyzer
from database import SOCDatabase
from guard import NetworkGuard
from ai_expert import AISecurityExpert

ctk.set_appearance_mode("dark")


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


class AutoSOCApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        load_env_file()

        # --- КОНФИГУРАЦИЯ ---
        self.db = SOCDatabase()
        latest_tg_user = self.db.get_latest_telegram_user()
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if not self.chat_id and latest_tg_user:
            self.chat_id = str(latest_tg_user[1])
        self.ai_expert = AISecurityExpert()
        self.guard = NetworkGuard(self.on_threat_detected)
        self.last_scan_data = []
        self.ai_chat_window = None
        self.ai_loader_job = None
        self.ai_loader_step = 0

        try:
            self.bot = telebot.TeleBot(self.bot_token) if self.bot_token else None
        except:
            self.bot = None

        if self.bot:
            self.start_telegram_listener()

        # Окно программы
        self.title("AutoSOC AI: Cyber Shield v2.6")
        self.geometry("1300x950")
        self.configure(fg_color="#0a0a0a")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkScrollableFrame(self, width=300, corner_radius=0, fg_color="#111111")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_columnconfigure(0, weight=1)

        self.logo = ctk.CTkLabel(self.sidebar, text="🛡️ AUTOSOC AI", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.pack(padx=20, pady=30)

        self.btn_scan = ctk.CTkButton(self.sidebar, text="🔍 ŞƏBƏKƏNİ TARA", fg_color="#1f538d",
                                      command=self.start_scan_thread, height=45, width=260)
        self.btn_scan.pack(padx=20, pady=10)

        self.btn_guard = ctk.CTkButton(self.sidebar, text="⚡ AI MÜHAFİZƏ: SÖNDÜ", fg_color="#8d1f1f",
                                       command=self.toggle_guard, height=45, width=260)
        self.btn_guard.pack(padx=20, pady=10)

        # --- SENSITIVITY ---
        self.slider_label = ctk.CTkLabel(self.sidebar, text="Həssaslıq (DDoS): 500", text_color="#777777")
        self.slider_label.pack(padx=20, pady=(15, 0))
        self.threshold_slider = ctk.CTkSlider(self.sidebar, from_=50, to=2000, command=self.update_threshold, width=260)
        self.threshold_slider.pack(padx=20, pady=10)
        self.threshold_slider.set(500)

        # --- FIREWALL SWITCHES ---
        self.fw_label = ctk.CTkLabel(self.sidebar, text="PORT İDARƏETMƏSİ", font=("Arial", 12, "bold"),
                                     text_color="#3498db")
        self.fw_label.pack(padx=20, pady=(20, 5))

        # Контейнер с прокруткой для портов
        self.ports_frame = ctk.CTkScrollableFrame(self.sidebar, width=260, height=280, fg_color="#0a0a0a")
        self.ports_frame.pack(padx=10, pady=5, fill="x")

        # Расширенный список портов
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
            27017: "MongoDB"
        }

        self.switches = {}

        # Кнопки управления всеми портами
        btn_frame = ctk.CTkFrame(self.ports_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=5, pady=(0, 10))

        btn_all_on = ctk.CTkButton(btn_frame, text="✓ Hamısını Aç", width=120, height=28,
                                   fg_color="#1a6b3c", hover_color="#27ae60",
                                   command=self.enable_all_ports)
        btn_all_on.pack(side="left", padx=2)

        btn_all_off = ctk.CTkButton(btn_frame, text="✕ Hamısını Bağla", width=120, height=28,
                                    fg_color="#8d1f1f", hover_color="#c0392b",
                                    command=self.disable_all_ports)
        btn_all_off.pack(side="left", padx=2)

        # Создаем переключатели для каждого порта
        for port, service in sorted(self.port_definitions.items()):
            switch = ctk.CTkSwitch(
                self.ports_frame,
                text=f"Port {port} ({service})",
                command=lambda p=port: self.toggle_port(p, self.switches[p])
            )
            switch.pack(padx=10, pady=3, anchor="w")
            switch.select()  # По умолчанию все порты открыты
            self.switches[port] = switch

        self.btn_history = ctk.CTkButton(self.sidebar, text="📜 AUDIT JURNALI", fg_color="transparent", border_width=1,
                                         command=self.show_history, width=260)
        self.btn_history.pack(padx=20, pady=15)

        # --- TELEGRAM ALERT SETTINGS ---
        self.tg_label = ctk.CTkLabel(
            self.sidebar,
            text="📩 TELEGRAM XƏBƏRDARLIQ",
            font=("Arial", 12, "bold"),
            text_color="#3498db"
        )
        self.tg_label.pack(padx=20, pady=(20, 5))

        self.tg_entry = ctk.CTkEntry(
            self.sidebar,
            width=260,
            height=38,
            placeholder_text="Telegram Chat ID...",
            fg_color="#0f0f0f",
            font=("Consolas", 12)
        )
        self.tg_entry.pack(padx=20, pady=5)
        if self.chat_id:
            self.tg_entry.insert(0, self.chat_id)

        self.tg_hint = ctk.CTkLabel(
            self.sidebar,
            text="ℹ️ ID-ni öyrənmək üçün\nbota /start yazın",
            font=("Arial", 10),
            text_color="#555555",
            justify="center"
        )
        self.tg_hint.pack(padx=20, pady=(0, 5))

        self.btn_open_bot = ctk.CTkButton(
            self.sidebar,
            text="🤖 Botu Telegram-da Aç",
            fg_color="transparent",
            border_width=1,
            border_color="#2980b9",
            text_color="#3498db",
            hover_color="#1a2a3a",
            height=35,
            width=260,
            command=lambda: __import__('webbrowser').open("https://t.me/AutoSOC_Baku_Bot")
        )
        self.btn_open_bot.pack(padx=20, pady=(0, 5))

        self.btn_save_tg = ctk.CTkButton(
            self.sidebar,
            text="💾 Yadda Saxla",
            fg_color="#1a6b3c",
            hover_color="#27ae60",
            height=35,
            width=260,
            command=self.save_telegram_id
        )
        self.btn_save_tg.pack(padx=20, pady=(5, 10))

        self.tg_status = ctk.CTkLabel(
            self.sidebar,
            text="",
            font=("Arial", 10),
            text_color="#2ecc71"
        )
        self.tg_status.pack(padx=20, pady=(0, 20))

        # --- MAIN TERMINAL ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#050505", border_width=1,
                                       border_color="#1a1a1a")
        self.main_frame.grid(row=0, column=1, padx=25, pady=25, sticky="nsew")

        self.status_label = ctk.CTkLabel(self.main_frame, text="● SİSTEM AKTİVDİR", text_color="#2ecc71",
                                         font=("Arial", 16, "bold"))
        self.status_label.pack(pady=20)

        self.ip_entry = ctk.CTkEntry(self.main_frame, width=550, height=45, placeholder_text="Hədəf IP...",
                                     fg_color="#0f0f0f", font=("Consolas", 14))
        self.ip_entry.pack(pady=10)
        try:
            self.ip_entry.insert(0, socket.gethostbyname(socket.gethostname()))
        except:
            self.ip_entry.insert(0, "127.0.0.1")

        self.result_box = ctk.CTkTextbox(self.main_frame, width=900, height=600, fg_color="#020202",
                                         text_color="#cfcfcf", font=("Consolas", 14))
        self.result_box.pack(pady=15, padx=25)

        self.result_box.tag_config("danger", foreground="#ff4d4d")
        self.result_box.tag_config("success", foreground="#2ecc71")
        self.result_box.tag_config("ai", foreground="#3498db")
        self.result_box.tag_config("info", foreground="#f1c40f")

        self.assistant_frame = ctk.CTkFrame(self.main_frame, fg_color="#0b1020", border_width=1, border_color="#1d2947")
        self.assistant_frame.pack(pady=(0, 20), padx=25, fill="x")

        self.assistant_title = ctk.CTkLabel(
            self.assistant_frame,
            text="AI Assistant",
            text_color="#00d4ff",
            font=("Arial", 15, "bold")
        )
        self.assistant_title.pack(anchor="w", padx=14, pady=(12, 6))

        self.assistant_output = ctk.CTkTextbox(
            self.assistant_frame,
            height=110,
            fg_color="#09101a",
            text_color="#d9e6ff",
            font=("Consolas", 12)
        )
        self.assistant_output.pack(fill="x", padx=14, pady=(0, 10))
        self.assistant_output.insert("end", "AI assistant hazırdır. Sual verin və ya son scan nəticəsini izah etməyimi istəyin.")

        self.assistant_prompt_row = ctk.CTkFrame(self.assistant_frame, fg_color="transparent")
        self.assistant_prompt_row.pack(fill="x", padx=14, pady=(0, 14))

        self.assistant_entry = ctk.CTkEntry(
            self.assistant_prompt_row,
            height=38,
            placeholder_text="Məsələn: 445 portu nə üçündür?",
            fg_color="#09101a"
        )
        self.assistant_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.assistant_button = ctk.CTkButton(
            self.assistant_prompt_row,
            text="Soruş",
            width=120,
            fg_color="#1f538d",
            command=self.ask_ai_assistant
        )
        self.assistant_button.pack(side="left")
        self.bind("<Control-Return>", lambda e: self.ask_ai_assistant())
        self.assistant_frame.pack_forget()
        self.assistant_output = None
        self.assistant_entry = None
        self.assistant_button = None

        self.ai_fab = ctk.CTkButton(
            self,
            text="AI",
            width=62,
            height=62,
            corner_radius=31,
            fg_color="#00b7ff",
            hover_color="#1593d1",
            text_color="#06111b",
            font=("Arial", 18, "bold"),
            command=self.open_ai_chat_window
        )
        self.ai_fab.place(relx=1.0, rely=1.0, x=-28, y=-28, anchor="se")
        self.ai_fab.lift()
        self.after(700, self.animate_ai_fab)

    # -------------------------------------------------------
    # PORT MANAGEMENT
    # -------------------------------------------------------
    def enable_all_ports(self):
        """Открыть все порты"""
        for port, switch in self.switches.items():
            if not switch.get():
                switch.select()
                self.toggle_port(port, switch)
        self.result_box.insert("0.0", "[FIREWALL] Bütün portlar AÇILDI\n", "success")

    def disable_all_ports(self):
        """Закрыть все порты"""
        for port, switch in self.switches.items():
            if switch.get():
                switch.deselect()
                self.toggle_port(port, switch)
        self.result_box.insert("0.0", "[FIREWALL] Bütün portlar BLOKLANDI\n", "danger")

    # -------------------------------------------------------
    # TELEGRAM
    # -------------------------------------------------------
    def save_telegram_id(self):
        new_id = self.tg_entry.get().strip()

        if not new_id:
            self.tg_status.configure(text="❌ Xana boşdur!", text_color="#ff4d4d")
            return

        self.chat_id = new_id
        self.tg_status.configure(text="⏳ Yoxlanılır...", text_color="#f1c40f")
        self.update()

        threading.Thread(target=self._send_test_message, daemon=True).start()

    def _send_test_message(self):
        try:
            if self.bot:
                self.bot.send_message(
                    self.chat_id,
                    "✅ *AutoSOC AI* qoşuldu!\nTəhdid xəbərdarlıqları buraya göndəriləcək.",
                    parse_mode="Markdown"
                )
                self.after(0, lambda: self.tg_status.configure(
                    text="✅ Saxlanıldı!", text_color="#2ecc71"
                ))
            else:
                self.after(0, lambda: self.tg_status.configure(
                    text="❌ Bot aktiv deyil", text_color="#ff4d4d"
                ))
        except Exception as e:
            self.after(0, lambda: self.tg_status.configure(
                text=f"❌ Xəta: {str(e)[:25]}", text_color="#ff4d4d"
            ))

    def send_telegram_alert(self, message: str):
        if not self.bot or not self.chat_id:
            return
        try:
            self.bot.send_message(self.chat_id, message, parse_mode="Markdown")
        except Exception as e:
            self.after(0, lambda: self.result_box.insert(
                "0.0", f"[TELEGRAM XƏTƏSİ]: {e}\n", "danger"
            ))

    # -------------------------------------------------------
    # ОСТАЛЬНАЯ ЛОГИКА
    # -------------------------------------------------------
    def toggle_port(self, port, switch_obj):
        is_open = switch_obj.get()
        action = "allow" if is_open else "block"
        rule_name = f"AutoSOC_Manual_{port}"
        os.system(f'netsh advfirewall firewall delete rule name="{rule_name}"')
        os.system(
            f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action={action} protocol=TCP localport={port}')

        status = "AÇIQ" if is_open else "BLOKLANDI"
        service = self.port_definitions.get(port, "Unknown")
        self.result_box.insert("0.0", f"[FIREWALL] Port {port} ({service}): {status}\n",
                               "success" if is_open else "danger")

    def update_threshold(self, value):
        self.guard.threshold = int(value)
        self.slider_label.configure(text=f"Həssaslıq (DDoS): {int(value)}")

    def toggle_guard(self):
        if not self.guard.is_monitoring:
            self.guard.start_monitoring()
            self.btn_guard.configure(text="⚡ AI MÜHAFİZƏ: AKTİVDİR", fg_color="#27ae60")
        else:
            self.guard.stop()
            self.btn_guard.configure(text="⚡ AI MÜHAFİZƏ: SÖNDÜ", fg_color="#8d1f1f")

    def on_threat_detected(self, ip, reason, cmd):
        alert_ui = f"\n[!] XƏBƏRDARLIQ: {ip} ünvanından müdaxilə\n[TƏDBİR]: AI tərəfindən bloklandı."
        self.after(0, lambda: self.result_box.insert("0.0", alert_ui + "\n", "danger"))

        alert_tg = (
            f"🚨 *AutoSOC AI — TƏHDİD AŞKARLANDI*\n\n"
            f"🔴 IP: `{ip}`\n"
            f"📌 Səbəb: {reason}\n"
            f"🛡 Tədbir: Avtomatik bloklandı"
        )
        threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()

    def start_telegram_listener(self):
        @self.bot.message_handler(commands=["start", "id"])
        def _start_handler(message):
            raw_payload = json.dumps(message.json, ensure_ascii=False) if getattr(message, "json", None) else "{}"
            print(f"[TELEGRAM][RAW] {raw_payload}")

            from_user = getattr(message, "from_user", None)
            user_id = getattr(from_user, "id", None)
            chat_id = getattr(getattr(message, "chat", None), "id", None)
            print(f"[TELEGRAM][PARSED] from.id={user_id} chat.id={chat_id}")

            if user_id is None or chat_id is None:
                return

            self.db.upsert_telegram_user(
                telegram_user_id=str(user_id),
                telegram_chat_id=str(chat_id),
                username=getattr(from_user, "username", "") if from_user else "",
                first_name=getattr(from_user, "first_name", "") if from_user else "",
                last_name=getattr(from_user, "last_name", "") if from_user else "",
                raw_payload=raw_payload,
            )

            self.chat_id = str(chat_id)
            self.after(0, self._sync_telegram_chat_id_ui)
            self.bot.reply_to(message, f"Your Telegram ID is: {user_id}\nChat ID is: {chat_id}")

        threading.Thread(target=self._poll_telegram_bot, daemon=True).start()

    def _poll_telegram_bot(self):
        try:
            self.bot.infinity_polling(skip_pending=True, timeout=20, long_polling_timeout=20)
        except Exception as exc:
            print(f"[TELEGRAM][POLLING_ERROR] {exc}")

    def _sync_telegram_chat_id_ui(self):
        if not hasattr(self, "tg_entry"):
            return
        self.tg_entry.delete(0, "end")
        self.tg_entry.insert(0, self.chat_id)
        self.tg_status.configure(text="Telegram ID captured from bot", text_color="#2ecc71")

    def animate_ai_fab(self):
        if not hasattr(self, "ai_fab"):
            return

        current = self.ai_fab.cget("fg_color")
        next_color = "#1593d1" if current == "#00b7ff" else "#00b7ff"
        self.ai_fab.configure(fg_color=next_color)
        self.after(900, self.animate_ai_fab)

    def open_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists():
            self.ai_chat_window.deiconify()
            self.ai_chat_window.lift()
            self.ai_chat_window.focus()
            return

        self.ai_chat_window = ctk.CTkToplevel(self)
        self.ai_chat_window.title("AutoSOC AI Assistant")
        self.ai_chat_window.geometry("420x520")
        self.ai_chat_window.attributes("-topmost", True)
        self.ai_chat_window.configure(fg_color="#0b1020")
        self.ai_chat_window.protocol("WM_DELETE_WINDOW", self.close_ai_chat_window)

        header = ctk.CTkFrame(self.ai_chat_window, fg_color="transparent")
        header.pack(fill="x", padx=14, pady=(14, 8))

        ctk.CTkLabel(
            header,
            text="AI Assistant",
            text_color="#00d4ff",
            font=("Arial", 16, "bold")
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="X",
            width=34,
            fg_color="#18233d",
            hover_color="#243252",
            command=self.close_ai_chat_window
        ).pack(side="right")

        self.assistant_output = ctk.CTkTextbox(
            self.ai_chat_window,
            height=340,
            fg_color="#09101a",
            text_color="#d9e6ff",
            font=("Consolas", 12)
        )
        self.assistant_output.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        self.assistant_output.insert("end", "Ask a cybersecurity question. Example: How do I protect against phishing?")

        self.assistant_loader = ctk.CTkLabel(
            self.ai_chat_window,
            text="",
            text_color="#7fb7ff",
            font=("Consolas", 11)
        )
        self.assistant_loader.pack(anchor="w", padx=14, pady=(0, 8))

        prompt_row = ctk.CTkFrame(self.ai_chat_window, fg_color="transparent")
        prompt_row.pack(fill="x", padx=14, pady=(0, 14))

        self.assistant_entry = ctk.CTkEntry(
            prompt_row,
            height=40,
            placeholder_text="Type your cybersecurity question..."
        )
        self.assistant_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.assistant_button = ctk.CTkButton(
            prompt_row,
            text="Send",
            width=90,
            fg_color="#1f538d",
            command=self.ask_ai_assistant
        )
        self.assistant_button.pack(side="left")
        self.assistant_entry.bind("<Return>", lambda e: self.ask_ai_assistant())

    def close_ai_chat_window(self):
        if self.ai_chat_window and self.ai_chat_window.winfo_exists():
            self.ai_chat_window.withdraw()

    def start_scan_thread(self):
        target = self.ip_entry.get()
        self.btn_scan.configure(state="disabled", text="⏳ Taranır...")
        self.result_box.delete("0.0", "end")
        threading.Thread(target=self.run_logic, args=(target,), daemon=True).start()

    def ask_ai_assistant(self):
        if not self.assistant_entry or not self.assistant_output:
            self.open_ai_chat_window()

        question = self.assistant_entry.get().strip()
        if not question:
            return

        self.assistant_output.delete("0.0", "end")
        self.assistant_output.insert("end", f"You: {question}\n\n")
        self.assistant_button.configure(state="disabled")
        self.assistant_entry.delete(0, "end")
        self.start_ai_loader()
        threading.Thread(target=self._run_ai_request, args=(question,), daemon=True).start()

    def _run_ai_request(self, question):
        answer = self.ai_expert.answer_question(question, self.last_scan_data)
        self.after(0, lambda: self._finish_ai_request(answer))

    def _finish_ai_request(self, answer):
        self.stop_ai_loader()
        if self.assistant_output:
            current_text = self.assistant_output.get("0.0", "end").strip()
            prefix = f"{current_text}\n\n" if current_text else ""
            self.assistant_output.delete("0.0", "end")
            self.assistant_output.insert("end", f"{prefix}AutoSOC AI: {answer}")
        if self.assistant_button:
            self.assistant_button.configure(state="normal")

    def start_ai_loader(self):
        self.ai_loader_step = 0
        self._tick_ai_loader()

    def _tick_ai_loader(self):
        if not getattr(self, "assistant_loader", None):
            return
        dots = "." * ((self.ai_loader_step % 3) + 1)
        self.assistant_loader.configure(text=f"Analyzing{dots}")
        self.ai_loader_step += 1
        self.ai_loader_job = self.after(350, self._tick_ai_loader)

    def stop_ai_loader(self):
        if self.ai_loader_job:
            self.after_cancel(self.ai_loader_job)
            self.ai_loader_job = None
        if getattr(self, "assistant_loader", None):
            self.assistant_loader.configure(text="")

    def run_logic(self, target):
        try:
            scanner = NetworkScanner()
            analyzer = RiskAnalyzer()
            data = scanner.scan_network(target, ports=list(self.port_definitions.keys()))
            self.result_box.insert("end", f">>> ŞƏBƏKƏ TƏFTİŞİ: {target}\n", "ai")

            self.last_scan_data = data
            if self.assistant_output:
                self.assistant_output.delete("0.0", "end")
                self.assistant_output.insert("end", self.ai_expert.summarize_scan(data))
            total_risks = 0
            for dev in data:
                vendor = list(dev['vendor'].values())[0] if dev['vendor'] else "Cihaz"
                self.result_box.insert("end", f"\n[+] {vendor} ({dev['ip']})\n")
                open_ports = dev.get('ports', [])
                if open_ports:
                    ports_view = ", ".join(
                        f"{item['port']} ({self.port_definitions.get(item['port'], item.get('name', 'Unknown'))})"
                        for item in open_ports
                    )
                    self.result_box.insert("end", f"    - AГ‡IQ PORTLAR: {ports_view}\n", "info")
                else:
                    self.result_box.insert("end", "    - SeГ§ilmiЕџ 22 port ГјzrЙ™ aГ§Д±q servis tapД±lmadД±\n", "success")

                risks = analyzer.analyze(dev['ports'])
                for r in risks:
                    if r['port'] in self.switches and not self.switches[r['port']].get():
                        self.result_box.insert("end", f"    - Port {r['port']}: [FIREWALL TƏRƏFİNDƏN İZOLƏ EDİLİB]\n",
                                               "ai")
                        continue

                    total_risks += 1
                    self.result_box.insert("end", f"    - Təhlükə: Port {r['port']} ({r['info']['service']})\n",
                                           "danger")
                    instruction = self.ai_expert.generate_instruction(vendor, r['port'], r['info']['service'])
                    self.result_box.insert("end", f"    💡 AI: {instruction}\n")

            if total_risks > 0:
                alert_tg = (
                    f"🔍 *AutoSOC AI — Tarama Nəticəsi*\n\n"
                    f"🎯 Hədəf: `{target}`\n"
                    f"⚠️ Aşkarlanan təhdid: *{total_risks}*\n"
                    f"📊 Risk səviyyəsi: *{min(total_risks * 25, 100)}%*"
                )
                threading.Thread(target=self.send_telegram_alert, args=(alert_tg,), daemon=True).start()
            else:
                self.result_box.insert("end", "\n✅ Heç bir təhlükə aşkarlanmadı.\n", "success")

            self.db.add_scan(target, min(total_risks * 25, 100), f"{total_risks} problem")
        except Exception as e:
            self.result_box.insert("end", f"\n[XƏTA]: {e}\n", "danger")
        finally:
            self.btn_scan.configure(state="normal", text="🔍 ŞƏBƏKƏNİ TARA")

    def show_history(self):
        win = ctk.CTkToplevel(self)
        win.title("Audit Jurnalı")
        win.geometry("600x400")
        win.attributes('-topmost', True)
        txt = ctk.CTkTextbox(win, width=550, height=350)
        txt.pack(padx=20, pady=20)
        for row in self.db.get_all_scans():
            txt.insert("end", f"{row[0]} | {row[1]} | {row[2]}%\n")


if __name__ == "__main__":
    import login


    def on_login_success(user):
        app = AutoSOCApp()
        app.title(f"AutoSOC AI: Cyber Shield v2.6  |  {user['username']} ({user['role']})")
        app.mainloop()


    login.launch(on_login_success)
