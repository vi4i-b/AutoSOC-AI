import random
import tkinter as tk
import math
import os
import json
import queue
import threading
import time
import webbrowser
import customtkinter as ctk
from tkinter import messagebox
from auth import init_db, verify_user, register_user, save_remember, load_remember, clear_remember, save_latest_telegram_user, get_latest_telegram_chat_id, is_telegram_chat_id_available
from runtime_support import TelegramBotClient, apply_window_icon, load_env_file, resource_path
from validators import validate_registration

ctk.set_appearance_mode("dark")
ctk.deactivate_automatic_dpi_awareness()
ctk.set_window_scaling(1.0)
ctk.set_widget_scaling(1.0)

# ─────────────────────────── COLOUR PALETTE ───────────────────────────
BG_DEEP       = "#07111b"      # outermost background
BG_CARD       = "#0b1623"      # main card fill
CARD_BORDER   = "#1d3347"      # card border
FIELD_BG      = "#0a1522"      # input field background
FIELD_BORDER  = "#29425c"      # input border (idle)
FIELD_FOCUS   = "#2b7fff"      # input border (focused)
TEXT_PRIMARY  = "#f4f8fc"      # main text
TEXT_MUTED    = "#87a5c0"      # labels / placeholders
ACCENT_CYAN   = "#77beff"      # "AI" highlight / accent
BTN_LEFT      = "#2b7fff"      # primary button
BTN_RIGHT     = "#2b7fff"
BTN_HOVER_L   = "#1f62ca"
BTN_HOVER_R   = "#1f62ca"
STAR_COLORS   = ["#ffffff", "#a0c8ff", "#60a0e0", "#304878"]
GLOW_COLOR    = "#0d2d6e"
TELEGRAM_BOT_URL = os.getenv("TELEGRAM_BOT_URL", "https://t.me/AutoSOC_Baku_Bot").strip()


# ═══════════════════════════ HELPERS ══════════════════════════════════

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


def _gradient_button(parent, text, command, width=300, height=46, radius=10):
    """Canvas-based button with a left→right gradient fill."""
    frame = tk.Frame(parent, bg=BG_CARD, bd=0, highlightthickness=0)

    c = tk.Canvas(frame, width=width, height=height, bd=0,
                  highlightthickness=0, bg=BG_CARD, cursor="hand2")
    c.pack()

    def _mask_corners(canvas, width, height, r, color):
        """Рисует маски по углам Canvas для эффекта плавного закругления."""
        # Левый верхний
        tl = [(0, 0), (r, 0)]
        for i in range(11):
            a = math.pi / 2 + (math.pi / 2) * (i / 10)
            tl.append((r + r * math.cos(a), r - r * math.sin(a)))
        tl.append((0, r))
        canvas.create_polygon(tl, fill=color, outline=color, smooth=False)

        # Правый верхний
        tr = [(width, 0), (width, r)]
        for i in range(11):
            a = (math.pi / 2) * (i / 10)
            tr.append((width - r + r * math.cos(a), r - r * math.sin(a)))
        tr.append((width - r, 0))
        canvas.create_polygon(tr, fill=color, outline=color, smooth=False)

        # Правый нижний
        br = [(width, height), (width - r, height)]
        for i in range(11):
            a = 3 * math.pi / 2 + (math.pi / 2) * (i / 10)
            br.append((width - r + r * math.cos(a), height - r - r * math.sin(a)))
        br.append((width, height - r))
        canvas.create_polygon(br, fill=color, outline=color, smooth=False)

        # Левый нижний
        bl = [(0, height), (0, height - r)]
        for i in range(11):
            a = math.pi + (math.pi / 2) * (i / 10)
            bl.append((r + r * math.cos(a), height - r - r * math.sin(a)))
        bl.append((r, height))
        canvas.create_polygon(bl, fill=color, outline=color, smooth=False)

    def _draw(lc, rc):
        c.delete("all")
        lr = int(lc[1:3], 16); lg = int(lc[3:5], 16); lb = int(lc[5:7], 16)
        rr = int(rc[1:3], 16); rg = int(rc[3:5], 16); rb = int(rc[5:7], 16)
        for i in range(width):
            t = i / (width - 1)
            r = int(lr + (rr - lr) * t)
            g = int(lg + (rg - lg) * t)
            b = int(lb + (rb - lb) * t)
            col = f"#{r:02x}{g:02x}{b:02x}"
            c.create_line(i, 0, i, height, fill=col)
        # rounded mask – draw corners as background colour
        for cx, cy in [(0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)]:
            pass
        # label
        c.create_text(width // 2, height // 2, text=text,
                      font=("Helvetica", 13, "bold"),
                      fill="#ffffff", anchor="center")

    _draw(BTN_LEFT, BTN_RIGHT)
    c.bind("<Button-1>",   lambda e: command())
    c.bind("<Enter>",      lambda e: _draw(BTN_HOVER_L, BTN_HOVER_R))
    c.bind("<Leave>",      lambda e: _draw(BTN_LEFT, BTN_RIGHT))
    return frame


def _draw_starfield(canvas, w, h):
    """Paint animated gradient background + stars on a tk.Canvas."""
    canvas.create_rectangle(0, 0, w, h, fill=BG_DEEP, outline="")


# ═══════════════════════════ SPLASH ═══════════════════════════════════

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
        W, H = _platform_layout(sw, sh, 720, 920, kind="splash")
        splash_scale = min(W / 720, H / 920)
        self.geometry(_center_geometry(sw, sh, W, H))
        self.attributes("-topmost", True)
        self.attributes("-alpha", 1.0)

        splash_bg = BG_DEEP
        self.configure(fg_color=splash_bg)
        bg = tk.Canvas(self, width=W, height=H, bg=splash_bg, highlightthickness=0, bd=0)
        bg.place(x=0, y=0)

        bg.create_oval(-140, -120, 240, 220, fill="#0b1623", outline="")
        bg.create_oval(W - 220, H - 200, W + 80, H + 80, fill="#0a1522", outline="")

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
                         bg=splash_bg, bd=0, highlightthickness=0).pack(pady=(0, 2))
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
                     text_color=TEXT_PRIMARY,
                     fg_color="transparent").pack(side="left")
        ctk.CTkLabel(row, text="AI",
                     font=ctk.CTkFont("Helvetica", title_font, "bold"),
                     text_color=ACCENT_CYAN,
                     fg_color="transparent").pack(side="left")

        ctk.CTkLabel(cf, text="Cyber Shield v2.6",
                     font=ctk.CTkFont("Helvetica", subtitle_font),
                     text_color=TEXT_MUTED,
                     fg_color="transparent").pack()

    def fade_out(self):
        if self._closed or not self.winfo_exists():
            return
        a = self.attributes("-alpha")
        if a > 0.05:
            self.attributes("-alpha", a - 0.05)
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


# ═══════════════════════════ LOGIN WINDOW ═════════════════════════════

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
        self.telegram_client = TelegramBotClient(os.getenv("TELEGRAM_BOT_TOKEN", "").strip())
        self.telegram_offset = None
        self.telegram_listener_running = False
        apply_window_icon(self)

        self.title("AutoSOC — Giriş")
        self.resizable(False, False)
        self.configure(fg_color=BG_DEEP)
        self.protocol("WM_DELETE_WINDOW", self._close_window)

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.window_width, self.window_height = _platform_layout(sw, sh, 1120, 720, kind="window")
        self.geometry(_center_geometry(sw, sh, self.window_width, self.window_height))

        self.withdraw()
        self._show_splash()
        self._ui_drain_after_id = self.after(120, self._drain_ui_queue)
        if self.telegram_client.enabled:
            self._start_telegram_listener()

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

    def _start_telegram_listener(self):
        if self.telegram_listener_running:
            return
        self.telegram_listener_running = True
        threading.Thread(target=self._telegram_polling_loop, daemon=True).start()

    def _telegram_polling_loop(self):
        while self.telegram_listener_running and self.telegram_client.enabled:
            ok, data = self.telegram_client.get_updates(offset=self.telegram_offset, timeout=20)
            if not ok:
                time.sleep(3)
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

        chat_id = message.get("chat", {}).get("id")
        from_user = message.get("from", {})
        user_id = from_user.get("id")
        text = (message.get("text") or "").strip()
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

        command = text.lower().split()[0].split("@")[0]
        if command in ("/start", "/id"):
            self.telegram_client.send_message(
                chat_id,
                (
                    "AutoSOC registration bot is active.\n"
                    f"Telegram User ID: {user_id}\n"
                    f"Telegram Chat ID: {chat_id}\n\n"
                    "Copy the Telegram Chat ID and paste it into the registration form."
                ),
            )

    def _sync_latest_telegram_chat_id(self, chat_id):
        if self._closing or not self.winfo_exists():
            return
        if hasattr(self, "telegram_entry") and self.telegram_entry.winfo_exists():
            self.telegram_entry.delete(0, "end")
            self.telegram_entry.insert(0, chat_id)

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
        self.telegram_listener_running = False
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

        # ── Background canvas ──
        bg = tk.Canvas(self, width=W, height=H,
                       highlightthickness=0, bd=0)
        bg.place(x=0, y=0)
        _draw_starfield(bg, W, H)

        glow = ctk.CTkFrame(
            self,
            width=card_width + 26,
            height=card_height + 26,
            fg_color="#0a1522",
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
            fg_color="#0d1b2a",
            corner_radius=26,
            border_width=1,
            border_color=CARD_BORDER,
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
                         bg="#0d1b2a", bd=0, highlightthickness=0).pack(pady=(18, 6))
            except tk.TclError:
                ctk.CTkLabel(card, text="🛡️",
                             font=("Arial", 44),
                             text_color=TEXT_PRIMARY,
                             fg_color="transparent").pack(pady=(18, 6))
        else:
            ctk.CTkLabel(card, text="🛡️",
                         font=("Arial", 44),
                         text_color=TEXT_PRIMARY,
                         fg_color="transparent").pack(pady=(18, 6))

        ctk.CTkLabel(
            card,
            text="AutoSOC",
            font=ctk.CTkFont("Helvetica", title_font, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack()
        ctk.CTkLabel(
            card,
            text="Secure access to your network monitoring cockpit",
            font=ctk.CTkFont("Helvetica", subtitle_font),
            text_color=TEXT_MUTED,
            wraplength=wraplength,
            justify="left",
        ).pack(pady=(6, 18))

        form = ctk.CTkScrollableFrame(
            card,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color="#23384d",
            scrollbar_button_hover_color="#2b7fff",
            width=card_width - (form_pad_x * 2),
            height=max(card_height - 210, 300),
        )
        form.pack(padx=form_pad_x, pady=(0, 16), fill="both", expand=True)

        # Username
        ctk.CTkLabel(form, text="İstifadəçi adı",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))
        self.username_entry = ctk.CTkEntry(
            form, height=44,
            placeholder_text="İstifadəçi adı",
            fg_color=FIELD_BG,
            border_color=FIELD_BORDER, border_width=1,
            corner_radius=10,
            font=ctk.CTkFont("Consolas", 13),
            text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_MUTED,
        )
        self.username_entry.pack(fill="x", pady=(0, 14))

        # Password
        ctk.CTkLabel(form, text="Şifrə",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))

        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.pack(fill="x", pady=(0, 18))

        self.password_entry = ctk.CTkEntry(
            pw_row, height=44,
            placeholder_text="••••••••",
            fg_color=FIELD_BG,
            border_color=FIELD_BORDER, border_width=1,
            corner_radius=10,
            font=ctk.CTkFont("Consolas", 13),
            text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_MUTED,
            show="•"
        )
        self.password_entry.pack(side="left", fill="x", expand=True)

        self.show_pw = False
        self.btn_eye = ctk.CTkButton(
            pw_row, text="👁", width=44, height=44,
            fg_color=FIELD_BG, hover_color="#152040",
            border_width=1, border_color=FIELD_BORDER,
            corner_radius=10,
            font=ctk.CTkFont("Arial", 14),
            command=self._toggle_pw
        )
        self.btn_eye.pack(side="left", padx=(6, 0))

        ctk.CTkLabel(form, text="Telegram Chat ID",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=TEXT_MUTED, anchor="w").pack(fill="x", pady=(0, 4))
        self.telegram_entry = ctk.CTkEntry(
            form, height=44,
            placeholder_text="Write /start to bot and paste Chat ID here",
            fg_color=FIELD_BG,
            border_color=FIELD_BORDER, border_width=1,
            corner_radius=10,
            font=ctk.CTkFont("Consolas", 13),
            text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_MUTED,
        )
        self.telegram_entry.pack(fill="x", pady=(0, 8))
        latest_chat_id = get_latest_telegram_chat_id()
        if latest_chat_id:
            self.telegram_entry.insert(0, latest_chat_id)

        tg_row = ctk.CTkFrame(form, fg_color="transparent")
        tg_row.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            tg_row,
            text="1. Write /start to the bot. 2. Copy Chat ID. 3. Paste it here for registration.",
            font=ctk.CTkFont("Helvetica", 10),
            text_color=TEXT_MUTED,
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
            border_color=FIELD_BORDER,
            hover_color="#121e38",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont("Helvetica", 11),
            corner_radius=10,
            command=lambda: webbrowser.open(TELEGRAM_BOT_URL),
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
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            text_color="#f4f8fc",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.attempt_login,
        )
        self.btn_login.pack(fill="x", pady=(0, 10))

        # ── Register (outline style) ───────────────────────────────────
        self.btn_register = ctk.CTkButton(
            form, text="📝  Qeydiyyat", height=40,
            fg_color="transparent",
            border_width=1, border_color=FIELD_BORDER,
            hover_color="#172433",
            text_color="#dbe8f4",
            font=ctk.CTkFont("Helvetica", 12),
            corner_radius=14,
            command=self.attempt_register
        )
        self.btn_register.pack(fill="x", pady=(0, 10))

        # ── Remember me + forgot ───────────────────────────────────────
        bottom_row = ctk.CTkFrame(form, fg_color="transparent")
        bottom_row.pack(fill="x")

        self.remember_var = ctk.BooleanVar()
        ctk.CTkCheckBox(
            bottom_row, text="Məni xatırla",
            variable=self.remember_var,
            font=ctk.CTkFont("Helvetica", 11),
            text_color=TEXT_MUTED,
            checkbox_width=16, checkbox_height=16,
            border_color=FIELD_BORDER,
            fg_color="#2b7fff",
            hover_color="#1f62ca",
            checkmark_color="#f4f8fc"
        ).pack(side="left")

        ctk.CTkLabel(
            bottom_row, text="Şifrəni unutmusunuz?",
            font=ctk.CTkFont("Helvetica", 11),
            text_color=TEXT_MUTED, cursor="hand2"
        ).pack(side="right")

        # ── Hotkey ────────────────────────────────────────────────────
        self.bind("<Return>", lambda e: self.attempt_login())

        # ── Autofill ──────────────────────────────────────────────────
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
        u = self.username_entry.get().strip()
        p = self.password_entry.get()
        if not u or not p:
            self.error_label.configure(text="⚠️ Bütün xanaları doldurun!")
            return
        user = verify_user(u, p)
        if user:
            save_remember(u) if self.remember_var.get() else clear_remember()
            self._close_window()
            self.on_success(user)
        else:
            self.error_label.configure(text="❌ İstifadəçi adı və ya şifrə yanlışdır!")
            self.password_entry.delete(0, "end")

    def attempt_register(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get()
        telegram_chat_id = self.telegram_entry.get().strip()
        if not u or not p or not telegram_chat_id:
            self.error_label.configure(text="⚠️ Qeydiyyat üçün username, password və Telegram Chat ID daxil edin!")
            return
        validation_error = validate_registration(u, p, telegram_chat_id)
        if validation_error:
            self.error_label.configure(text=f"⚠️ {validation_error}")
            return
        if not is_telegram_chat_id_available(telegram_chat_id):
            self.error_label.configure(text="⚠️ Bu Telegram Chat ID artıq başqa hesab üçün istifadə olunub.")
            return
        if register_user(u, p, telegram_chat_id=telegram_chat_id):
            self.error_label.configure(
                text="✅ Qeydiyyat uğurlu! Daxil olun.",
                text_color="#2ecc71"
            )
            messagebox.showinfo("AutoSOC", f"'{u}' istifadəçisi yaradıldı!\nTelegram Chat ID linked: {telegram_chat_id}")
        else:
            self.error_label.configure(
                text="❌ Bu istifadəçi artıq mövcuddur!",
                text_color="#ff5555"
            )


# ═══════════════════════════ ENTRY POINT ══════════════════════════════

def launch(on_success):
    app = LoginWindow(on_success)
    app.mainloop()
