"""Telegram notifier with alert aggregation, rate limiting, and i18n.

Two protections against flooding the Bot API (and getting rate-limited/banned):

1. **Aggregation** — alerts with the same signature (tenant/agent/technique)
   arriving within a short window are collapsed into a single "N similar
   alerts" message instead of N messages.
2. **Rate limiting** — a minimum interval is enforced between sends to any one
   chat.

Messages are localized per tenant language, and critical alerts carry an
inline **Rollback** button. A pluggable ``send_func`` keeps it fully testable
without hitting the network.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

import httpx

from app.config import settings
from app.i18n import t

log = logging.getLogger("autosoc.telegram")


@dataclass
class Alert:
    chat_id: str
    lang: str
    key: str                       # i18n key
    params: dict = field(default_factory=dict)
    signature: str = ""            # alerts sharing a signature are aggregated
    rollback_incident: str = ""    # if set, attach a Rollback button
    bot_token: str = ""            # per-tenant bot token (from encrypted creds)


@dataclass
class _Bucket:
    alert: Alert
    count: int
    first_ts: float


class TelegramNotifier:
    def __init__(self, send_func=None) -> None:
        # send_func(bot_token, chat_id, text, buttons) -> awaitable; default = real HTTP.
        self._send_func = send_func or self._http_send
        self._pending: dict[tuple[str, str], _Bucket] = {}
        self._last_send: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._flush_loop(), name="telegram-flush")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def enqueue(self, alert: Alert) -> None:
        key = (alert.chat_id, alert.signature or alert.key)
        async with self._lock:
            bucket = self._pending.get(key)
            if bucket:
                bucket.count += 1
            else:
                self._pending[key] = _Bucket(alert=alert, count=1, first_ts=time.monotonic())

    async def _flush_loop(self) -> None:
        while self._running:
            await asyncio.sleep(0.5)
            try:
                await self._flush_matured()
            except Exception:
                log.exception("telegram flush failed")

    async def _flush_matured(self) -> None:
        now = time.monotonic()
        due: list[_Bucket] = []
        async with self._lock:
            for key in list(self._pending):
                if now - self._pending[key].first_ts >= settings.telegram_aggregate_window_s:
                    due.append(self._pending.pop(key))
        for bucket in due:
            await self._deliver(bucket)

    async def _deliver(self, bucket: _Bucket) -> None:
        alert = bucket.alert
        if bucket.count > 1:
            params = dict(alert.params, count=bucket.count,
                          window=int(settings.telegram_aggregate_window_s))
            text = t("incident.aggregated", alert.lang, **params)
        else:
            text = t(alert.key, alert.lang, **alert.params)

        buttons = None
        if alert.rollback_incident:
            buttons = [[{"text": t("action.rollback", alert.lang),
                         "callback_data": f"rollback:{alert.rollback_incident}"}]]

        await self._rate_limited_send(alert.bot_token, alert.chat_id, text, buttons)

    async def _rate_limited_send(self, bot_token, chat_id, text, buttons) -> None:
        # Enforce a minimum gap between sends to the same chat.
        wait = 0.0
        last = self._last_send.get(chat_id, 0.0)
        gap = time.monotonic() - last
        if gap < settings.telegram_min_send_interval_s:
            wait = settings.telegram_min_send_interval_s - gap
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_send[chat_id] = time.monotonic()
        try:
            await self._send_func(bot_token, chat_id, text, buttons)
        except Exception:
            log.exception("telegram send failed for chat %s", chat_id)

    async def _http_send(self, bot_token, chat_id, text, buttons) -> None:
        token = bot_token or settings.telegram_bot_token
        if not token:
            log.info("[telegram-disabled] %s: %s", chat_id, text)
            return
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload)
            resp.raise_for_status()


notifier = TelegramNotifier()
