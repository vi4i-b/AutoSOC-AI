"""Login and registration window with splash screen."""

import json
import os
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox

import customtkinter as ctk

from autosoc.auth import (
    AccountLockedError,
    clear_remember,
    get_latest_telegram_chat_id,
    init_db,
    is_telegram_chat_id_available,
    register_account,
    registration_mode,
    load_remember,
    register_user,
    save_latest_telegram_user,
    save_remember,
    verify_user,
)
from autosoc.env import load_env_file
from autosoc.paths import resource_path
from autosoc.telegram.client import TelegramBotClient
from autosoc.telegram.listener import TelegramUpdateListener, extract_command, extract_contact
from autosoc.ui import theme
from autosoc.ui.theme import apply_window_icon
from autosoc.validators import validate_registration

ctk.set_appearance_mode("dark")
ctk.deactivate_automatic_dpi_awareness()
ctk.set_window_scaling(1.0)
ctk.set_widget_scaling(1.0)

TELEGRAM_BOT_URL_DEFAULT = "https://t.me/AutoSOC_Baku_Bot"


def _platform_layout(screen_w, screen_h, base_w, base_h, *, kind="window"):
    """Scale splash/login windows consistently across platforms."""
    width_ratio = 0.32 if kind == "splash" else 0.34
    height_ratio = 0.80 if kind == "splash" else 0.86
    margin = 90
    max_scale = 1.20
    min_scale = 0.78
    width = max(int(base_w * min_scale), min(int(base_w * max_scale), int(screen_w * width_ratio)))
    height = max(int(base_h * min_scale), min(int(base_h * max_scale), int((screen_h - margin) * height_ratio)))
    return width, height


def _center_geometry(screen_w, screen_h, width, height):
    x = max((screen_w - width) // 2, 0)
    y = max((screen_h - height) // 2, 0)
    return f"{width}x{height}+{x}+{y}"


class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent, on_done):
        super().__init__(parent)
        self.on_done = on_done
        self.logo_image = None
        self._fade_after_id = None
        self._closed = False
        self.overrideredirect(True)
        apply_window_icon(self)

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        width, height = _platform_layout(sw, sh, 720, 920, kind="splash")
        splash_scale = min(width / 720, height / 920)
        self.geometry(_center_geometry(sw, sh, width, height))
        self.attributes("-topmost", True)
        self.attributes("-alpha", 1.0)

        self.configure(fg_color=theme.BG_DEEP)
        bg = tk.Canvas(self, width=width, height=height, bg=theme.BG_DEEP, highlightthickness=0, bd=0)
        bg.place(x=0, y=0)

        bg.create_oval(-140, -120, 240, 220, fill=theme.BG_SIDEBAR, outline="")
        bg.create_oval(width - 220, height - 200, width + 80, height + 80, fill=theme.BG_FIELD, outline="")

        cf = ctk.CTkFrame(self, fg_color="transparent")
        cf.place(relx=.5, rely=.5, anchor="center")
        title_font = max(42, int(54 * splash_scale))
        subtitle_font = max(18, int(20 * splash_scale))

        logo_path = resource_path("assets", "autosoc_logo_splash.png")
        if os.path.exists(logo_path):
            try:
                logo_image = tk.PhotoImage(file=logo_path)
                self.logo_image = logo_image
                tk.Label(cf, image=self.logo_image, text="",
                         bg=theme.BG_DEEP, bd=0, highlightthickness=0).pack(pady=(0, 2))
            except tk.TclError:
                ctk.CTkLabel(cf, text="🛡️", font=("Arial", 56),
                             fg_color="transparent").pack(pady=(0, 10))
        else:
            ctk.CTkLabel(cf, text="🛡️", font=("Arial", 56),
                         fg_color="transparent").pack(pady=(0, 10))

        row = ctk.CTkFrame(cf, fg_color="transparent")
        row.pack(pady=(0, max(12, int(14 * splash_scale))))
        ctk.CTkLabel(row, text="AutoSOC",
                     font=ctk.CTkFont("Helvetica", title_font, "bold"),
                     text_color=theme.TEXT_PRIMARY,
                     fg_color="transparent").pack(side="left")
        ctk.CTkLabel(row, text="AI",
                     font=ctk.CTkFont("Helvetica", title_font, "bold"),
                     text_color=theme.ACCENT_CYAN,
                     fg_color="transparent").pack(side="left")

        ctk.CTkLabel(cf, text="Cyber Shield v3.0",
                     font=ctk.CTkFont("Helvetica", subtitle_font),
                     text_color=theme.TEXT_MUTED,
                     fg_color="transparent").pack()

    def fade_out(self):
        if self._closed or not self.winfo_exists():
            return
        alpha = self.attributes("-alpha")
        if alpha > 0.05:
            self.attributes("-alpha", alpha - 0.05)
            self._fade_after_id = self.after(20, self.fade_out)
        else:
            self.safe_close()
            if callable(self.on_done):
                self.on_done()

    def safe_close(self):
        if self._closed:
            return
        self._closed = True
        if self._fade_after_id is not None:
            try:
                self.after_cancel(self._fade_after_id)
            except tk.TclError:
                pass
            self._fade_after_id = None
        if self.winfo_exists():
            self.destroy()


class LoginWindow(ctk.CTk):
    def __init__(self, on_success):
        super().__init__()
        self.on_success = on_success
        self.login_logo_image = None
        self.splash = None
        self._splash_after_id = None
        self._ui_drain_after_id = None
        self._closing = False
        self.ui_queue = queue.Queue()
        load_env_file()
        init_db()
        self.telegram_bot_url = (os.getenv("TELEGRAM_BOT_URL") or TELEGRAM_BOT_URL_DEFAULT).strip()
        self.telegram_client = TelegramBotClient(os.getenv("TELEGRAM_BOT_TOKEN", "").strip())
        self.telegram_listener = TelegramUpdateListener(
            self.telegram_client,
            on_update=self._handle_telegram_update,
        )
        apply_window_icon(self)

        self.title("AutoSOC — Giriş")
        self.resizable(False, False)
        self.configure(fg_color=theme.BG_DEEP)
        self.protocol("WM_DELETE_WINDOW", self._close_window)

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.window_width, self.window_height = _platform_layout(sw, sh, 1120, 720, kind="window")
        self.geometry(_center_geometry(sw, sh, self.window_width, self.window_height))

        self.withdraw()
        self._show_splash()
        self._ui_drain_after_id = self.after(120, self._drain_ui_queue)
        self.telegram_listener.start()

    # ── splash ──────────────────────────────────────────────────────
    def _show_splash(self):
        self.splash = SplashScreen(self, on_done=self._after_fade)
        self._splash_after_id = self.after(1600, self._trigger_splash_fade)

    def _trigger_splash_fade(self):
        self._splash_after_id = None
        if self._closing:
            return
        if self.splash and self.splash.winfo_exists():
            self.splash.fade_out()

    def _after_fade(self):
        if self._closing or not self.winfo_exists():
            return
        self._build_ui()
        self.deiconify()

    # ── telegram ────────────────────────────────────────────────────
    def _handle_telegram_update(self, update):
        contact = extract_contact(update)
        if not contact:
            return
        chat_id, user_id, text, from_user = contact
        if chat_id is None or user_id is None or not text:
            return

        save_latest_telegram_user(
            telegram_user_id=str(user_id),
            telegram_chat_id=str(chat_id),
            username=from_user.get("username", ""),
            first_name=from_user.get("first_name", ""),
            last_name=from_user.get("last_name", ""),
            raw_payload=json.dumps(update, ensure_ascii=False),
        )
        self._safe_after(0, lambda cid=str(chat_id): self._sync_latest_telegram_chat_id(cid))

        if extract_command(text) in ("start", "id"):
            self.telegram_client.send_message(
                chat_id,
                (
                    "AutoSOC registration bot is active.\n"
                    f"Telegram User ID: {user_id}\n"
                    f"Telegram Chat ID: {chat_id}\n\n"
                    "Copy the Telegram Chat ID and paste it into the registration form."
                ),
                parse_mode=None,
            )

    def _sync_latest_telegram_chat_id(self, chat_id):
        if self._closing or not self.winfo_exists():
            return
        if hasattr(self, "telegram_entry") and self.telegram_entry.winfo_exists():
            self.telegram_entry.delete(0, "end")
            self.telegram_entry.insert(0, chat_id)

    # ── thread-safe UI plumbing ─────────────────────────────────────
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
            if not self._closing and self.winfo_exists():
                self._ui_drain_after_id = self.after(120, self._drain_ui_queue)
        except tk.TclError:
            pass

    def _safe_after(self, delay_ms, callback):
        if self._closing or not self.winfo_exists():
            return None
        if threading.current_thread() is not threading.main_thread():
            self.ui_queue.put(callback)
            return True
        try:
            return self.after(delay_ms, callback)
        except tk.TclError:
            return None

    def _close_window(self):
        if self._closing:
            return
        self._closing = True
        self.telegram_listener.stop()
        if self._splash_after_id is not None:
            try:
                self.after_cancel(self._splash_after_id)
            except tk.TclError:
                pass
            self._splash_after_id = None
        if self._ui_drain_after_id is not None:
            try:
                self.after_cancel(self._ui_drain_after_id)
            except tk.TclError:
                pass
            self._ui_drain_after_id = None
        if self.splash is not None:
            try:
                self.splash.safe_close()
            except tk.TclError:
                pass
        self.destroy()

    # ── build UI ─────────────────────────────────────────────────────
    def _build_ui(self):
        W, H = self.window_width, self.window_height
        card_width = max(min(W - 80, 520), 420)
        card_height = max(min(H - 90, 690), 560)
        form_pad_x = max(int(card_width * 0.09), 26)
        wraplength = max(card_width - (form_pad_x * 2), 260)
        title_font = max(28, min(32, int(card_width * 0.07)))
        subtitle_font = max(11, min(13, int(card_width * 0.026)))

        bg = tk.Canvas(self, width=W, height=H, highlightthickness=0, bd=0)
        bg.place(x=0, y=0)
        bg.create_rectangle(0, 0, W, H, fill=theme.BG_DEEP, outline="")

        glow = ctk.CTkFrame(
            self,
            width=card_width + 26,
            height=card_height + 26,
            fg_color=theme.BG_FIELD,
            corner_radius=30,
            border_width=1,
            border_color="#142433",
        )
        glow.place(relx=.5, rely=.5, anchor="center")
        glow.pack_propagate(False)

        card = ctk.CTkFrame(
            glow,
            width=card_width,
            height=card_height,
            fg_color=theme.BG_PANEL,
            corner_radius=26,
            border_width=1,
            border_color=theme.CARD_BORDER,
        )
        card.place(relx=.5, rely=.5, anchor="center")
        card.pack_propagate(False)

        # ── Header ─────────────────────────────────────────────────────
        logo_path = resource_path("assets", "autosoc_logo_login.png")
        if os.path.exists(logo_path):
            try:
                login_logo = tk.PhotoImage(file=logo_path)
                self.login_logo_image = login_logo
                tk.Label(card, image=self.login_logo_image, text="",
                         bg=theme.BG_PANEL, bd=0, highlightthickness=0).pack(pady=(18, 6))
            except tk.TclError:
                ctk.CTkLabel(card, text="🛡️",
                             font=("Arial", 44),
                             text_color=theme.TEXT_PRIMARY,
                             fg_color="transparent").pack(pady=(18, 6))
        else:
            ctk.CTkLabel(card, text="🛡️",
                         font=("Arial", 44),
                         text_color=theme.TEXT_PRIMARY,
                         fg_color="transparent").pack(pady=(18, 6))

        ctk.CTkLabel(
            card,
            text="AutoSOC",
            font=ctk.CTkFont("Helvetica", title_font, "bold"),
            text_color=theme.TEXT_PRIMARY,
        ).pack()
        ctk.CTkLabel(
            card,
            text="Secure access to your network monitoring cockpit",
            font=ctk.CTkFont("Helvetica", subtitle_font),
            text_color=theme.TEXT_MUTED,
            wraplength=wraplength,
            justify="left",
        ).pack(pady=(6, 18))

        form = ctk.CTkScrollableFrame(
            card,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color="#23384d",
            scrollbar_button_hover_color=theme.ACCENT_BLUE,
            width=card_width - (form_pad_x * 2),
            height=max(card_height - 210, 300),
        )
        form.pack(padx=form_pad_x, pady=(0, 16), fill="both", expand=True)

        # Username
        ctk.CTkLabel(form, text="İstifadəçi adı",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=theme.TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))
        self.username_entry = ctk.CTkEntry(
            form, height=44,
            placeholder_text="İstifadəçi adı",
            fg_color=theme.BG_FIELD,
            border_color=theme.FIELD_BORDER, border_width=1,
            corner_radius=10,
            font=ctk.CTkFont("Consolas", 13),
            text_color=theme.TEXT_PRIMARY,
            placeholder_text_color=theme.TEXT_MUTED,
        )
        self.username_entry.pack(fill="x", pady=(0, 14))

        # Password
        ctk.CTkLabel(form, text="Şifrə",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=theme.TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))

        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.pack(fill="x", pady=(0, 18))

        self.password_entry = ctk.CTkEntry(
            pw_row, height=44,
            placeholder_text="••••••••",
            fg_color=theme.BG_FIELD,
            border_color=theme.FIELD_BORDER, border_width=1,
            corner_radius=10,
            font=ctk.CTkFont("Consolas", 13),
            text_color=theme.TEXT_PRIMARY,
            placeholder_text_color=theme.TEXT_MUTED,
            show="•"
        )
        self.password_entry.pack(side="left", fill="x", expand=True)

        self.show_pw = False
        self.btn_eye = ctk.CTkButton(
            pw_row, text="👁", width=44, height=44,
            fg_color=theme.BG_FIELD, hover_color="#152040",
            border_width=1, border_color=theme.FIELD_BORDER,
            corner_radius=10,
            font=ctk.CTkFont("Arial", 14),
            command=self._toggle_pw
        )
        self.btn_eye.pack(side="left", padx=(6, 0))

        ctk.CTkLabel(form, text="Telegram Chat ID",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=theme.TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))
        self.telegram_entry = ctk.CTkEntry(
            form, height=44,
            placeholder_text="Write /start to bot and paste Chat ID here",
            fg_color=theme.BG_FIELD,
            border_color=theme.FIELD_BORDER, border_width=1,
            corner_radius=10,
            font=ctk.CTkFont("Consolas", 13),
            text_color=theme.TEXT_PRIMARY,
            placeholder_text_color=theme.TEXT_MUTED,
        )
        self.telegram_entry.pack(fill="x", pady=(0, 8))
        latest_chat_id = get_latest_telegram_chat_id()
        if latest_chat_id:
            self.telegram_entry.insert(0, latest_chat_id)

        # Invite code — shown only when the deployment restricts registration.
        self.invite_entry = None
        if registration_mode() != "open":
            ctk.CTkLabel(form, text="Invite code",
                         font=ctk.CTkFont("Helvetica", 11),
                         text_color=theme.TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))
            self.invite_entry = ctk.CTkEntry(
                form, height=44,
                placeholder_text="inv-… (from an administrator)",
                fg_color=theme.BG_FIELD,
                border_color=theme.FIELD_BORDER, border_width=1,
                corner_radius=10,
                font=ctk.CTkFont("Consolas", 13),
                text_color=theme.TEXT_PRIMARY,
                placeholder_text_color=theme.TEXT_MUTED,
            )
            self.invite_entry.pack(fill="x", pady=(0, 8))

        tg_row = ctk.CTkFrame(form, fg_color="transparent")
        tg_row.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            tg_row,
            text="1. Write /start to the bot. 2. Copy Chat ID. 3. Paste it here for registration.",
            font=ctk.CTkFont("Helvetica", 10),
            text_color=theme.TEXT_MUTED,
            justify="left",
            wraplength=wraplength - 80,
        ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            tg_row,
            text="Open Bot",
            width=108,
            height=30,
            fg_color="transparent",
            border_width=1,
            border_color=theme.FIELD_BORDER,
            hover_color="#121e38",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont("Helvetica", 11),
            corner_radius=10,
            command=lambda: webbrowser.open(self.telegram_bot_url),
        ).pack(side="right", padx=(8, 0))

        # Error label
        self.error_label = ctk.CTkLabel(
            form, text="",
            font=ctk.CTkFont("Helvetica", 11),
            text_color="#ff5555",
            wraplength=wraplength
        )
        self.error_label.pack(fill="x", pady=(0, 8))

        self.btn_login = ctk.CTkButton(
            form,
            text="Daxil ol",
            height=46,
            corner_radius=14,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            text_color=theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.attempt_login,
        )
        self.btn_login.pack(fill="x", pady=(0, 10))

        self.btn_register = ctk.CTkButton(
            form, text="📝  Qeydiyyat", height=40,
            fg_color="transparent",
            border_width=1, border_color=theme.FIELD_BORDER,
            hover_color=theme.BTN_OUTLINE_HOVER,
            text_color="#dbe8f4",
            font=ctk.CTkFont("Helvetica", 12),
            corner_radius=14,
            command=self.attempt_register
        )
        self.btn_register.pack(fill="x", pady=(0, 10))

        # ── Remember me ────────────────────────────────────────────────
        bottom_row = ctk.CTkFrame(form, fg_color="transparent")
        bottom_row.pack(fill="x")

        self.remember_var = ctk.BooleanVar()
        ctk.CTkCheckBox(
            bottom_row, text="Məni xatırla",
            variable=self.remember_var,
            font=ctk.CTkFont("Helvetica", 11),
            text_color=theme.TEXT_MUTED,
            checkbox_width=16, checkbox_height=16,
            border_color=theme.FIELD_BORDER,
            fg_color=theme.ACCENT_BLUE,
            hover_color=theme.ACCENT_BLUE_HOVER,
            checkmark_color=theme.TEXT_PRIMARY
        ).pack(side="left")

        self.bind("<Return>", lambda e: self.attempt_login())

        saved = load_remember()
        if saved:
            self.username_entry.insert(0, saved)
            self.remember_var.set(True)
            self.password_entry.focus()
        else:
            self.username_entry.focus()

    # ── Actions ───────────────────────────────────────────────────────
    def _toggle_pw(self):
        self.show_pw = not self.show_pw
        self.password_entry.configure(show="" if self.show_pw else "•")
        self.btn_eye.configure(text="🙈" if self.show_pw else "👁")

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.error_label.configure(text="⚠️ Bütün xanaları doldurun!")
            return
        try:
            user = verify_user(username, password)
        except AccountLockedError as exc:
            minutes = max(exc.retry_after_seconds // 60, 1)
            self.error_label.configure(
                text=f"⛔ Hesab müvəqqəti kilidlənib. {minutes} dəqiqə sonra yenidən cəhd edin."
            )
            self.password_entry.delete(0, "end")
            return

        if user:
            save_remember(username) if self.remember_var.get() else clear_remember()
            self._close_window()
            self.on_success(user)
        else:
            self.error_label.configure(text="❌ İstifadəçi adı və ya şifrə yanlışdır!")
            self.password_entry.delete(0, "end")

    def attempt_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        telegram_chat_id = self.telegram_entry.get().strip()
        if not username or not password or not telegram_chat_id:
            self.error_label.configure(text="⚠️ Qeydiyyat üçün username, password və Telegram Chat ID daxil edin!")
            return
        validation_error = validate_registration(username, password, telegram_chat_id)
        if validation_error:
            self.error_label.configure(text=f"⚠️ {validation_error}")
            return
        if not is_telegram_chat_id_available(telegram_chat_id):
            self.error_label.configure(text="⚠️ Bu Telegram Chat ID artıq başqa hesab üçün istifadə olunub.")
            return

        invite_code = self.invite_entry.get().strip() if self.invite_entry else ""
        ok, message = register_account(username, password,
                                       telegram_chat_id=telegram_chat_id, invite_code=invite_code)
        if ok:
            self.error_label.configure(text=f"✅ {message} Daxil olun.", text_color="#2ecc71")
            messagebox.showinfo("AutoSOC", f"'{username}': {message}")
        else:
            self.error_label.configure(text=f"❌ {message}", text_color="#ff5555")


def launch(on_success):
    app = LoginWindow(on_success)
    app.mainloop()
