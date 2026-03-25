import sys
import random
import tkinter as tk
import math
import customtkinter as ctk
from tkinter import messagebox
from auth import init_db, verify_user, register_user, save_remember, load_remember, clear_remember

ctk.set_appearance_mode("dark")

# ─────────────────────────── COLOUR PALETTE ───────────────────────────
BG_DEEP       = "#080e1f"      # outermost background
BG_CARD       = "#0d1b3e"      # card fill
CARD_BORDER   = "#1b3060"      # card border
FIELD_BG      = "#0a1428"      # input field background
FIELD_BORDER  = "#1b3060"      # input border (idle)
FIELD_FOCUS   = "#2a6dd9"      # input border (focused)
TEXT_PRIMARY  = "#e8f0ff"      # main text
TEXT_MUTED    = "#5a80a8"      # labels / placeholders
ACCENT_CYAN   = "#00d4ff"      # "AI" highlight / gradient end
BTN_LEFT      = "#1a7fd4"      # gradient button left  (blue)
BTN_RIGHT     = "#00c8a0"      # gradient button right (teal-green)
BTN_HOVER_L   = "#2290e8"
BTN_HOVER_R   = "#00ddb0"
STAR_COLORS   = ["#ffffff", "#a0c8ff", "#60a0e0", "#304878"]
GLOW_COLOR    = "#0d2d6e"


# ═══════════════════════════ HELPERS ══════════════════════════════════

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
    # Vertical gradient
    steps = h
    for i in range(steps):
        t = i / steps
        r = int(8  + t * 10)
        g = int(14 + t * 18)
        b = int(31 + t * 40)
        canvas.create_line(0, i, w, i, fill=f"#{r:02x}{g:02x}{b:02x}")

    # Soft glow blobs
    canvas.create_oval(-120, -120, 260, 260,
                       fill="#0b254d", outline="")
    canvas.create_oval(w - 200, h - 200, w + 120, h + 120,
                       fill="#0a1e45", outline="")
    canvas.create_oval(w // 2 - 80, 0, w // 2 + 80, 160,
                       fill="#0d2860", outline="", stipple="gray25")

    # Stars
    random.seed(99)
    for _ in range(90):
        x = random.randint(0, w)
        y = random.randint(0, h)
        size = random.choices([1, 1, 2], weights=[6, 3, 1])[0]
        col  = random.choice(STAR_COLORS)
        canvas.create_oval(x, y, x + size, y + size, fill=col, outline="")


# ═══════════════════════════ SPLASH ═══════════════════════════════════

class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent, on_done):
        super().__init__(parent)
        self.on_done = on_done
        self.overrideredirect(True)

        W, H = 480, 620
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        self.attributes("-topmost", True)
        self.attributes("-alpha", 1.0)

        if sys.platform == "win32":
            MASK = "#010101"
            self.configure(bg=MASK)
            self.attributes("-transparentcolor", MASK)
            cv = tk.Canvas(self, width=W, height=H, bg=MASK, highlightthickness=0)
            cv.place(x=0, y=0)
            self._rounded_rect(cv, 0, 0, W, H, r=28, fill=BG_CARD)
        else:
            self.configure(fg_color=BG_CARD)

        cf = ctk.CTkFrame(self, fg_color="transparent")
        cf.place(relx=.5, rely=.5, anchor="center")

        ctk.CTkLabel(cf, text="🛡️", font=("Arial", 56),
                     fg_color="transparent").pack(pady=(0, 10))

        row = ctk.CTkFrame(cf, fg_color="transparent")
        row.pack()
        ctk.CTkLabel(row, text="AutoSOC",
                     font=ctk.CTkFont("Helvetica", 30, "bold"),
                     text_color=TEXT_PRIMARY,
                     fg_color="transparent").pack(side="left")
        ctk.CTkLabel(row, text="AI",
                     font=ctk.CTkFont("Helvetica", 30, "bold"),
                     text_color=ACCENT_CYAN,
                     fg_color="transparent").pack(side="left")

        ctk.CTkLabel(cf, text="Cyber Shield v2.6",
                     font=ctk.CTkFont("Consolas", 12),
                     text_color=TEXT_MUTED,
                     fg_color="transparent").pack(pady=(6, 0))

    def _rounded_rect(self, canvas, x1, y1, x2, y2, r, **kw):
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r,
               x2, y2-r, x2, y2, x2-r, y2, x1+r, y2,
               x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        canvas.create_polygon(pts, smooth=True, **kw)

    def fade_out(self):
        a = self.attributes("-alpha")
        if a > 0.05:
            self.attributes("-alpha", a - 0.05)
            self.after(20, self.fade_out)
        else:
            self.destroy()
            self.on_done()


# ═══════════════════════════ LOGIN WINDOW ═════════════════════════════

class LoginWindow(ctk.CTk):
    def __init__(self, on_success):
        super().__init__()
        self.on_success = on_success
        init_db()

        self.title("AutoSOC AI — Giriş")
        self.resizable(False, False)
        self.configure(fg_color=BG_DEEP)

        W, H = 480, 660
        self.geometry(f"{W}x{H}")
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        self.withdraw()
        self._show_splash()

    # ── splash ──────────────────────────────────────────────────────
    def _show_splash(self):
        self.splash = SplashScreen(self, on_done=self._after_fade)
        self.after(1600, self.splash.fade_out)

    def _after_fade(self):
        self._build_ui()
        self.deiconify()

    # ── build UI ─────────────────────────────────────────────────────
    def _build_ui(self):
        W, H = 480, 660

        # ── Background canvas ──
        bg = tk.Canvas(self, width=W, height=H,
                       highlightthickness=0, bd=0)
        bg.place(x=0, y=0)
        _draw_starfield(bg, W, H)

        # ── Card ──────────────────────────────────────────────────────
        CARD_W, CARD_H = 360, 520
        card = ctk.CTkFrame(self,
                            width=CARD_W, height=CARD_H,
                            fg_color=BG_CARD,
                            corner_radius=22,
                            border_width=1,
                            border_color=CARD_BORDER)
        card.place(relx=.5, rely=.5, anchor="center")
        card.pack_propagate(False)

        # ── Logo + title ───────────────────────────────────────────────
        ctk.CTkLabel(card, text="🛡️",
                     font=("Arial", 44),
                     fg_color="transparent").pack(pady=(30, 4))

        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.pack()
        ctk.CTkLabel(title_row, text="AutoSOC",
                     font=ctk.CTkFont("Helvetica", 26, "bold"),
                     text_color=TEXT_PRIMARY,
                     fg_color="transparent").pack(side="left")
        ctk.CTkLabel(title_row, text="AI",
                     font=ctk.CTkFont("Helvetica", 26, "bold"),
                     text_color=ACCENT_CYAN,
                     fg_color="transparent").pack(side="left")

        ctk.CTkLabel(card,
                     text="Təhlükəsizlik monitorinq sistemi",
                     font=ctk.CTkFont("Helvetica", 11),
                     text_color=TEXT_MUTED,
                     fg_color="transparent").pack(pady=(4, 20))

        # ── Form ───────────────────────────────────────────────────────
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(padx=32, fill="x")

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

        # Error label
        self.error_label = ctk.CTkLabel(
            form, text="",
            font=ctk.CTkFont("Helvetica", 11),
            text_color="#ff5555",
            wraplength=280
        )
        self.error_label.pack(pady=(0, 6))

        # ── Gradient login button ──────────────────────────────────────
        btn_frame = _gradient_button(
            form, text="Daxil ol",
            command=self.attempt_login,
            width=296, height=46
        )
        btn_frame.pack(fill="x", pady=(0, 8))

        # ── Register (outline style) ───────────────────────────────────
        self.btn_register = ctk.CTkButton(
            form, text="📝  Qeydiyyat", height=40,
            fg_color="transparent",
            border_width=1, border_color=FIELD_BORDER,
            hover_color="#121e38",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont("Helvetica", 12),
            corner_radius=10,
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
            checkmark_color=ACCENT_CYAN
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
            self.destroy()
            self.on_success(user)
        else:
            self.error_label.configure(text="❌ İstifadəçi adı və ya şifrə yanlışdır!")
            self.password_entry.delete(0, "end")

    def attempt_register(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get()
        if not u or not p:
            self.error_label.configure(text="⚠️ Qeydiyyat üçün məlumatları doldurun!")
            return
        if len(u) < 3 or len(p) < 4:
            self.error_label.configure(text="⚠️ Minimum: Ad 3, Şifrə 4 simvol")
            return
        if register_user(u, p):
            self.error_label.configure(
                text="✅ Qeydiyyat uğurlu! Daxil olun.",
                text_color="#2ecc71"
            )
            messagebox.showinfo("AutoSOC AI", f"'{u}' istifadəçisi yaradıldı!")
        else:
            self.error_label.configure(
                text="❌ Bu istifadəçi artıq mövcuddur!",
                text_color="#ff5555"
            )


# ═══════════════════════════ ENTRY POINT ══════════════════════════════

def launch(on_success):
    app = LoginWindow(on_success)
    app.mainloop()