"""Shared color palette and small UI helpers."""

import os
import tkinter as tk

from autosoc.paths import resource_path

# ── Core palette ───────────────────────────────────────────────────────
BG_DEEP = "#07111b"        # outermost background
BG_SIDEBAR = "#0b1623"     # sidebar / large panels
BG_CARD = "#101c2b"        # sidebar cards
BG_PANEL = "#0d1b2a"       # right-side cards
BG_CONSOLE = "#08111b"     # text consoles
BG_FIELD = "#0a1522"       # input fields
CARD_BORDER = "#1d3347"
FIELD_BORDER = "#29425c"

TEXT_PRIMARY = "#f4f8fc"
TEXT_SOFT = "#dce8f2"
TEXT_MUTED = "#87a5c0"
TEXT_FAINT = "#7f95ab"

ACCENT_BLUE = "#2b7fff"
ACCENT_BLUE_HOVER = "#1f62ca"
ACCENT_CYAN = "#77beff"
ACCENT_GREEN = "#5dd39e"
ACCENT_GREEN_DARK = "#1f805d"
ACCENT_GREEN_DARK_HOVER = "#166446"
ACCENT_RED = "#ff6b7a"
ACCENT_RED_DARK = "#88344d"
ACCENT_RED_DARK_HOVER = "#6d263c"
ACCENT_YELLOW = "#ffd36b"

STATUS_OK = "#6bf0a7"
STATUS_GOOD = "#7fe3b1"
STATUS_WARN = "#ffd36b"
STATUS_ERROR = "#ff8a8a"
STATUS_DANGER = "#ff7c85"

BTN_NEUTRAL = "#243244"
BTN_NEUTRAL_HOVER = "#31445b"
BTN_OUTLINE_HOVER = "#172433"
BTN_OUTLINE_BORDER = "#2b425a"


def apply_window_icon(window):
    png_path = resource_path("assets", "app_icon.png")
    ico_path = resource_path("assets", "app_icon.ico")
    try:
        if os.path.exists(png_path):
            window._app_icon_image = tk.PhotoImage(file=png_path)
            window.iconphoto(True, window._app_icon_image)
        if os.name == "nt" and os.path.exists(ico_path):
            window.iconbitmap(ico_path)
    except tk.TclError:
        pass
