"""Minimal Telegram Bot API client.

Security notes:
 - The bot token is part of the request URL, so every error message passes
   through :meth:`TelegramBotClient._redact` before leaving this module —
   otherwise a network exception could leak the token into the UI or logs.
 - Dynamic values interpolated into Markdown messages should be escaped
   with :func:`escape_markdown` by the caller.
"""

import requests

from autosoc.logging_setup import get_logger

log = get_logger("telegram.client")

_MARKDOWN_SPECIALS = "_*`["


def escape_markdown(value) -> str:
    """Escape Telegram (legacy) Markdown special characters in dynamic text."""
    text = str(value)
    for char in _MARKDOWN_SPECIALS:
        text = text.replace(char, f"\\{char}")
    return text


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
            description = self._redact(str(exc))
            log.debug("Telegram %s failed: %s", method_name, description)
            return False, {"description": description}

    def _redact(self, text: str) -> str:
        if self.token:
            text = text.replace(self.token, "***TOKEN***")
        return text
