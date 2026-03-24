import customtkinter as ctk
import threading
import socket
import telebot
import os
from tkinter import messagebox

# Импорт твоих модулей
from scanner import NetworkScanner
from analyzer import RiskAnalyzer
from database import SOCDatabase
from guard import NetworkGuard
from ai_expert import AISecurityExpert

ctk.set_appearance_mode("dark")


class AutoSOCApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- КОНФИГУРАЦИЯ ---
        self.bot_token = "8692665055:AAFJin9pRNYhx-Y9BjDriSV2E_DEjCJoblI"
        self.chat_id = "1863304152"

        self.db = SOCDatabase()
        self.ai_expert = AISecurityExpert()
        self.guard = NetworkGuard(self.on_threat_detected)

        try:
            self.bot = telebot.TeleBot(self.bot_token)
        except:
            self.bot = None

        # Окно программы
        self.title("AutoSOC AI: Cyber Shield v2.6")
        self.geometry("1300x950")
        self.configure(fg_color="#0a0a0a")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=300, corner_radius=0, fg_color="#111111")
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.logo = ctk.CTkLabel(self.sidebar, text="🛡️ AUTOSOC AI", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=30)

        self.btn_scan = ctk.CTkButton(self.sidebar, text="🔍 ŞƏBƏKƏNİ TARA", fg_color="#1f538d",
                                      command=self.start_scan_thread, height=45)
        self.btn_scan.grid(row=1, column=0, padx=20, pady=10)

        self.btn_guard = ctk.CTkButton(self.sidebar, text="⚡ AI MÜHAFİZƏ: SÖNDÜ", fg_color="#8d1f1f",
                                       command=self.toggle_guard, height=45)
        self.btn_guard.grid(row=2, column=0, padx=20, pady=10)

        # --- SENSITIVITY ---
        self.slider_label = ctk.CTkLabel(self.sidebar, text="Həssaslıq (DDoS): 500", text_color="#777777")
        self.slider_label.grid(row=3, column=0, padx=20, pady=(15, 0))
        self.threshold_slider = ctk.CTkSlider(self.sidebar, from_=50, to=2000, command=self.update_threshold)
        self.threshold_slider.grid(row=4, column=0, padx=20, pady=10)
        self.threshold_slider.set(500)

        # --- FIREWALL SWITCHES ---
        self.fw_label = ctk.CTkLabel(self.sidebar, text="PORT İDARƏETMƏSİ", font=("Arial", 12, "bold"),
                                     text_color="#3498db")
        self.fw_label.grid(row=5, column=0, padx=20, pady=(20, 5))

        self.switches = {
            3389: ctk.CTkSwitch(self.sidebar, text="Port 3389 (RDP)",
                                command=lambda: self.toggle_port(3389, self.switches[3389])),
            80: ctk.CTkSwitch(self.sidebar, text="Port 80 (HTTP)",
                              command=lambda: self.toggle_port(80, self.switches[80])),
            22: ctk.CTkSwitch(self.sidebar, text="Port 22 (SSH)",
                              command=lambda: self.toggle_port(22, self.switches[22])),
            139: ctk.CTkSwitch(self.sidebar, text="Port 139 (NetBIOS)",
                               command=lambda: self.toggle_port(139, self.switches[139]))
        }

        row_idx = 6
        for p in self.switches:
            self.switches[p].grid(row=row_idx, column=0, padx=20, pady=5)
            self.switches[p].select()
            row_idx += 1

        self.btn_history = ctk.CTkButton(self.sidebar, text="📜 AUDIT JURNALI", fg_color="transparent", border_width=1,
                                         command=self.show_history)
        self.btn_history.grid(row=12, column=0, padx=20, pady=25)

        # --- TELEGRAM ALERT SETTINGS ---
        self.tg_label = ctk.CTkLabel(
            self.sidebar,
            text="📩 TELEGRAM XƏBƏRDARLIQ",
            font=("Arial", 12, "bold"),
            text_color="#3498db"
        )
        self.tg_label.grid(row=13, column=0, padx=20, pady=(20, 5))

        self.tg_entry = ctk.CTkEntry(
            self.sidebar,
            width=220,
            height=38,
            placeholder_text="Telegram Chat ID...",
            fg_color="#0f0f0f",
            font=("Consolas", 12)
        )
        self.tg_entry.grid(row=14, column=0, padx=20, pady=5)
        self.tg_entry.insert(0, self.chat_id)

        self.tg_hint = ctk.CTkLabel(
            self.sidebar,
            text="ℹ️ ID-ni öyrənmək üçün\nbota /start yazın",
            font=("Arial", 10),
            text_color="#555555",
            justify="center"
        )
        self.tg_hint.grid(row=15, column=0, padx=20, pady=(0, 5))

        self.btn_open_bot = ctk.CTkButton(
            self.sidebar,
            text="🤖 Botu Telegram-da Aç",
            fg_color="transparent",
            border_width=1,
            border_color="#2980b9",
            text_color="#3498db",
            hover_color="#1a2a3a",
            height=35,
            command=lambda: __import__('webbrowser').open("https://t.me/AutoSOC_Baku_Bot")
        )
        self.btn_open_bot.grid(row=16, column=0, padx=20, pady=(0, 5))

        self.btn_save_tg = ctk.CTkButton(
            self.sidebar,
            text="💾 Yadda Saxla",
            fg_color="#1a6b3c",
            hover_color="#27ae60",
            height=35,
            command=self.save_telegram_id
        )
        self.btn_save_tg.grid(row=17, column=0, padx=20, pady=(5, 10))

        self.tg_status = ctk.CTkLabel(
            self.sidebar,
            text="",
            font=("Arial", 10),
            text_color="#2ecc71"
        )
        self.tg_status.grid(row=18, column=0, padx=20, pady=0)

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
        self.result_box.insert("0.0", f"[FIREWALL] Port {port} statusu: {status}\n", "success" if is_open else "danger")

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

    def start_scan_thread(self):
        target = self.ip_entry.get()
        self.btn_scan.configure(state="disabled", text="⏳ Taranır...")
        self.result_box.delete("0.0", "end")
        threading.Thread(target=self.run_logic, args=(target,), daemon=True).start()

    def run_logic(self, target):
        try:
            scanner = NetworkScanner()
            analyzer = RiskAnalyzer()
            data = scanner.scan_network(target)
            self.result_box.insert("end", f">>> ŞƏBƏKƏ TƏFTİŞİ: {target}\n", "ai")

            total_risks = 0
            for dev in data:
                vendor = list(dev['vendor'].values())[0] if dev['vendor'] else "Cihaz"
                self.result_box.insert("end", f"\n[+] {vendor} ({dev['ip']})\n")

                risks = analyzer.analyze(dev['ports'])
                for r in risks:
                    if r['port'] in self.switches and not self.switches[r['port']].get():
                        self.result_box.insert("end", f"    - Port {r['port']}: [FIREWALL TƏRƏFİNDƏN İZOLƏ EDİLİB]\n", "ai")
                        continue

                    total_risks += 1
                    self.result_box.insert("end", f"    - Təhlükə: Port {r['port']} ({r['info']['service']})\n", "danger")
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