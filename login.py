import customtkinter as ctk
from auth import init_db, verify_user, save_remember, load_remember, clear_remember

ctk.set_appearance_mode("dark")


class LoginWindow(ctk.CTk):
    def __init__(self, on_success):
        super().__init__()

        self.on_success = on_success  # Ana pəncərəni açmaq üçün callback

        init_db()  # DB-ni yarat (əgər yoxdursa)

        self.title("AutoSOC AI — Giriş")
        self.geometry("480x560")
        self.resizable(False, False)
        self.configure(fg_color="#0a0a0a")

        # --- LOGO ---
        ctk.CTkLabel(self, text="🛡️", font=("Arial", 60)).pack(pady=(50, 5))
        ctk.CTkLabel(self, text="AUTOSOC AI", font=ctk.CTkFont(size=26, weight="bold")).pack()
        ctk.CTkLabel(self, text="Cyber Shield v2.6", font=("Arial", 12),
                     text_color="#555555").pack(pady=(0, 40))

        # --- FORM ---
        self.frame = ctk.CTkFrame(self, fg_color="#111111", corner_radius=15)
        self.frame.pack(padx=40, fill="x")

        ctk.CTkLabel(self.frame, text="İstifadəçi adı", font=("Arial", 12),
                     text_color="#777777", anchor="w").pack(padx=25, pady=(25, 2), fill="x")

        self.username_entry = ctk.CTkEntry(
            self.frame, height=42, placeholder_text="admin",
            fg_color="#0f0f0f", font=("Consolas", 13)
        )
        self.username_entry.pack(padx=25, fill="x")

        ctk.CTkLabel(self.frame, text="Şifrə", font=("Arial", 12),
                     text_color="#777777", anchor="w").pack(padx=25, pady=(15, 2), fill="x")

        # Şifrə sahəsi + göster/gizlet
        self.pw_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        self.pw_frame.pack(padx=25, fill="x")

        self.password_entry = ctk.CTkEntry(
            self.pw_frame, height=42, placeholder_text="••••••••",
            fg_color="#0f0f0f", font=("Consolas", 13), show="•"
        )
        self.password_entry.pack(side="left", fill="x", expand=True)

        self.show_pw = False
        self.btn_eye = ctk.CTkButton(
            self.pw_frame, text="👁", width=42, height=42,
            fg_color="#0f0f0f", hover_color="#1a1a1a",
            command=self.toggle_password
        )
        self.btn_eye.pack(side="left", padx=(5, 0))

        # Məni xatırla
        self.remember_var = ctk.BooleanVar()
        self.remember_check = ctk.CTkCheckBox(
            self.frame, text="Məni xatırla",
            variable=self.remember_var,
            font=("Arial", 12), text_color="#777777"
        )
        self.remember_check.pack(padx=25, pady=(15, 5), anchor="w")

        # Xəta mesajı
        self.error_label = ctk.CTkLabel(
            self.frame, text="", font=("Arial", 11),
            text_color="#ff4d4d"
        )
        self.error_label.pack(padx=25, pady=(0, 5))

        # Giriş düyməsi
        self.btn_login = ctk.CTkButton(
            self.frame, text="🔐 Daxil ol", height=45,
            fg_color="#1f538d", hover_color="#2980b9",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.attempt_login
        )
        self.btn_login.pack(padx=25, pady=(5, 25), fill="x")

        # Enter ilə giriş
        self.bind("<Return>", lambda e: self.attempt_login())

        # Əgər "Məni xatırla" saxlanıbsa — istifadəçi adını doldur
        saved_user = load_remember()
        if saved_user:
            self.username_entry.insert(0, saved_user)
            self.remember_var.set(True)
            self.password_entry.focus()
        else:
            self.username_entry.focus()

    def toggle_password(self):
        self.show_pw = not self.show_pw
        self.password_entry.configure(show="" if self.show_pw else "•")
        self.btn_eye.configure(text="🙈" if self.show_pw else "👁")

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            self.error_label.configure(text="⚠️ Bütün xanaları doldurun!")
            return

        self.btn_login.configure(state="disabled", text="⏳ Yoxlanılır...")
        self.update()

        user = verify_user(username, password)

        if user:
            # Məni xatırla
            if self.remember_var.get():
                save_remember(username)
            else:
                clear_remember()

            self.destroy()
            self.on_success(user)
        else:
            self.error_label.configure(text="❌ İstifadəçi adı və ya şifrə yanlışdır!")
            self.btn_login.configure(state="normal", text="🔐 Daxil ol")
            self.password_entry.delete(0, "end")
            self.password_entry.focus()


def launch(on_success):
    app = LoginWindow(on_success)
    app.mainloop()