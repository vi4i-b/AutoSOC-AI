import customtkinter as ctk
from tkinter import messagebox
from auth import init_db, verify_user, register_user, save_remember, load_remember, clear_remember

ctk.set_appearance_mode("dark")


class LoginWindow(ctk.CTk):
    def __init__(self, on_success):
        super().__init__()

        self.on_success = on_success  # Callback для запуска AutoSOCApp

        init_db()  # Инициализация БД и создание admin:admin123

        self.title("AutoSOC AI — Giriş")
        self.geometry("480x620")  # Немного увеличил высоту для новой кнопки
        self.resizable(False, False)
        self.configure(fg_color="#0a0a0a")

        # --- LOGO ---
        ctk.CTkLabel(self, text="🛡️", font=("Arial", 60)).pack(pady=(40, 5))
        ctk.CTkLabel(self, text="AUTOSOC AI", font=ctk.CTkFont(size=26, weight="bold")).pack()
        ctk.CTkLabel(self, text="Cyber Shield v2.6", font=("Arial", 12),
                     text_color="#555555").pack(pady=(0, 30))

        # --- FORM FRAME ---
        self.frame = ctk.CTkFrame(self, fg_color="#111111", corner_radius=15)
        self.frame.pack(padx=40, fill="x")

        # Поле логина
        ctk.CTkLabel(self.frame, text="İstifadəçi adı", font=("Arial", 12),
                     text_color="#777777", anchor="w").pack(padx=25, pady=(20, 2), fill="x")
        self.username_entry = ctk.CTkEntry(
            self.frame, height=42, placeholder_text="admin",
            fg_color="#0f0f0f", font=("Consolas", 13)
        )
        self.username_entry.pack(padx=25, fill="x")

        # Поле пароля
        ctk.CTkLabel(self.frame, text="Şifrə", font=("Arial", 12),
                     text_color="#777777", anchor="w").pack(padx=25, pady=(15, 2), fill="x")

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

        # Чекбокс "Запомнить меня"
        self.remember_var = ctk.BooleanVar()
        self.remember_check = ctk.CTkCheckBox(
            self.frame, text="Məni xatırla",
            variable=self.remember_var,
            font=("Arial", 12), text_color="#777777"
        )
        self.remember_check.pack(padx=25, pady=(15, 5), anchor="w")

        # Метка ошибок
        self.error_label = ctk.CTkLabel(
            self.frame, text="", font=("Arial", 11),
            text_color="#ff4d4d"
        )
        self.error_label.pack(padx=25, pady=(0, 5))

        # КНОПКА ВХОДА
        self.btn_login = ctk.CTkButton(
            self.frame, text="🔐 Daxil ol", height=45,
            fg_color="#1f538d", hover_color="#2980b9",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.attempt_login
        )
        self.btn_login.pack(padx=25, pady=(5, 10), fill="x")

        # КНОПКА РЕГИСТРАЦИИ
        self.btn_register = ctk.CTkButton(
            self.frame, text="📝 Qeydiyyat", height=38,
            fg_color="transparent", border_width=1, border_color="#1f538d",
            hover_color="#1a1a1a",
            font=ctk.CTkFont(size=13),
            command=self.attempt_register
        )
        self.btn_register.pack(padx=25, pady=(0, 25), fill="x")

        # Горячие клавиши
        self.bind("<Return>", lambda e: self.attempt_login())

        # Автозаполнение логина
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
            self.error_label.configure(text="⚠️ Bütün xanaları doldurun!", text_color="#ff4d4d")
            return

        user = verify_user(username, password)

        if user:
            if self.remember_var.get():
                save_remember(username)
            else:
                clear_remember()

            self.destroy()
            self.on_success(user)
        else:
            self.error_label.configure(text="❌ İstifadəçi adı və ya şifrə yanlışdır!", text_color="#ff4d4d")
            self.password_entry.delete(0, "end")

    def attempt_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            self.error_label.configure(text="⚠️ Qeydiyyat üçün məlumatları doldurun!", text_color="#ff4d4d")
            return

        if len(username) < 3 or len(password) < 4:
            self.error_label.configure(text="⚠️ Minimum: Ad 3, Şifrə 4 simvol", text_color="#ff4d4d")
            return

        if register_user(username, password):
            self.error_label.configure(text="✅ Qeydiyyat uğurlu! Daxil olun.", text_color="#2ecc71")
            messagebox.showinfo("AutoSOC AI", f"'{username}' istifadəçisi yaradıldı!")
        else:
            self.error_label.configure(text="❌ Bu istifadəçi artıq mövcuddur!", text_color="#ff4d4d")


def launch(on_success):
    app = LoginWindow(on_success)
    app.mainloop()