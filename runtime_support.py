import os
import sys
import tkinter as tk

import requests


def resource_path(*parts):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, *parts)


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


def load_env_file(path=".env"):
    candidates = []
    if path:
        candidates.append(path)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.extend(
        [
            os.path.join(os.getcwd(), ".env"),
            os.path.join(base_dir, ".env"),
            os.path.join(os.path.dirname(base_dir), ".env"),
        ]
    )

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.extend(
            [
                os.path.join(exe_dir, ".env"),
                os.path.join(os.path.dirname(exe_dir), ".env"),
            ]
        )

    seen = set()
    for candidate in candidates:
        normalized = os.path.abspath(candidate)
        if normalized in seen or not os.path.exists(normalized):
            continue
        seen.add(normalized)
        try:
            with open(normalized, "r", encoding="utf-8") as env_file:
                for raw_line in env_file:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
            return
        except OSError:
            continue


class TelegramBotClient:
    def __init__(self, token):
        self.token = (token or "").strip()
        self.base_url = f"https://api.telegram.org/bot{self.token}" if self.token else ""
        self.enabled = bool(self.token)

    def get_me(self):
        if not self.enabled:
            return False, {"description": "Telegram bot token is empty"}
        return self._request("getMe", method="get")

    def get_updates(self, offset=None, timeout=25):
        if not self.enabled:
            return False, {"description": "Telegram bot token is empty"}
        payload = {"timeout": timeout}
        if offset is not None:
            payload["offset"] = offset
        return self._request("getUpdates", method="get", payload=payload, timeout=timeout + 10)

    def send_message(self, chat_id, text, parse_mode="Markdown"):
        if not self.enabled:
            return False, {"description": "Telegram bot token is empty"}
        payload = {"chat_id": str(chat_id), "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        return self._request("sendMessage", method="post", payload=payload, timeout=30)

    def _request(self, method_name, method="get", payload=None, timeout=30):
        try:
            if method == "post":
                response = requests.post(
                    f"{self.base_url}/{method_name}",
                    json=payload or {},
                    timeout=timeout,
                )
            else:
                response = requests.get(
                    f"{self.base_url}/{method_name}",
                    params=payload or {},
                    timeout=timeout,
                )
            response.raise_for_status()
            data = response.json()
            return bool(data.get("ok")), data
        except Exception as exc:
            return False, {"description": str(exc)}
