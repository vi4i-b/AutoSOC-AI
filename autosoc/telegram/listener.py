"""Background long-polling listener for Telegram updates.

Shared by the login window and the dashboard, so the polling loop exists in
exactly one place. Callbacks are invoked from the listener thread — UI code
must marshal back to the Tk main loop itself.
"""

import threading
import time

from autosoc.logging_setup import get_logger

log = get_logger("telegram.listener")


def extract_contact(update):
    """Pull (chat_id, user_id, text, from_user) out of an update, or None."""
    message = update.get("message") or update.get("edited_message")
    if not message:
        return None
    text = (message.get("text") or "").strip()
    chat_id = message.get("chat", {}).get("id")
    from_user = message.get("from", {})
    user_id = from_user.get("id")
    return chat_id, user_id, text, from_user


def extract_command(text):
    """Normalize '/start@BotName arg' to 'start'; plain text returns ''."""
    normalized = (text or "").strip().lower()
    if not normalized.startswith("/"):
        return ""
    return normalized.split()[0].split("@")[0].lstrip("/")


class TelegramUpdateListener:
    def __init__(self, client, on_update, on_state=None, poll_timeout=20, retry_delay=4):
        """``on_update(update)`` per update; ``on_state(healthy, description)`` on health changes."""
        self.client = client
        self.on_update = on_update
        self.on_state = on_state
        self.poll_timeout = int(poll_timeout)
        self.retry_delay = retry_delay
        self.offset = None
        self.healthy = False
        self._running = False
        self._thread = None

    @property
    def running(self):
        return self._running

    def start(self):
        if self._running or not self.client.enabled:
            return False
        self._running = True
        self.healthy = False
        self._thread = threading.Thread(target=self._poll_loop, name="AutoSOCTelegramListener", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._running = False

    def _poll_loop(self):
        while self._running and self.client.enabled:
            ok, data = self.client.get_updates(offset=self.offset, timeout=self.poll_timeout)
            if not self._running:
                break

            if not ok:
                description = data.get("description", "unknown error")
                self._set_state(False, description)
                time.sleep(self.retry_delay)
                continue

            self._set_state(True, "")

            for update in data.get("result", []):
                update_id = update.get("update_id")
                if update_id is not None:
                    self.offset = update_id + 1
                try:
                    self.on_update(update)
                except Exception:
                    log.exception("Unhandled error in Telegram update handler")

    def _set_state(self, healthy, description):
        if healthy == self.healthy:
            return
        self.healthy = healthy
        if not healthy:
            log.warning("Telegram listener degraded: %s", description)
        if self.on_state:
            try:
                self.on_state(healthy, description)
            except Exception:
                log.exception("Unhandled error in Telegram state handler")
