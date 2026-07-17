"""FortiGate SOAR client with an async retry policy.

Network calls to the firewall are wrapped in bounded exponential backoff with
jitter: transient failures (timeouts, connection errors, 5xx) are retried;
permanent ones (4xx, auth) fail fast. The API token is decrypted from the
tenant's AES-256 credential only in memory, and is redacted from every error
string so it can never leak into logs or Telegram.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass

import httpx

from app.config import settings

log = logging.getLogger("autosoc.fortigate")

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass
class SoarResult:
    ok: bool
    message: str
    reference: str = ""
    attempts: int = 0


class FortiGateClient:
    def __init__(self, host: str, api_token: str, *, vdom: str = "root",
                 address_group: str = "AutoSOC_Blocklist", verify_tls: bool | None = None) -> None:
        self.host = host.rstrip("/")
        if self.host and "://" not in self.host:
            self.host = "https://" + self.host
        self._token = api_token
        self.vdom = vdom or "root"
        self.group = address_group or "AutoSOC_Blocklist"
        self.verify_tls = settings.fortigate_verify_tls if verify_tls is None else verify_tls

    # ── public actions ───────────────────────────────────────────────

    async def block_ip(self, ip: str, comment: str = "AutoSOC") -> SoarResult:
        name = f"AutoSOC_{ip}"
        addr_body = {"name": name, "subnet": f"{ip}/32", "comment": comment[:255]}
        r1 = await self._request("POST", "firewall/address", json=addr_body, tolerate={200, 500})
        if not r1.ok:
            return r1
        r2 = await self._request("POST", f"firewall/addrgrp/{self.group}/member",
                                 json={"name": name}, tolerate={200, 424})
        return SoarResult(r2.ok, r2.message, reference=name, attempts=r1.attempts + r2.attempts)

    async def unblock_ip(self, ip: str) -> SoarResult:
        name = f"AutoSOC_{ip}"
        return await self._request("DELETE", f"firewall/addrgrp/{self.group}/member/{name}",
                                   tolerate={200, 404}, reference=name)

    # ── retrying request core ────────────────────────────────────────

    async def _request(self, method: str, path: str, *, json: dict | None = None,
                       tolerate: set[int] | None = None, reference: str = "") -> SoarResult:
        tolerate = tolerate or {200}
        url = f"{self.host}/api/v2/cmdb/{path}"
        params = {"vdom": self.vdom, "access_token": self._token}
        last_error = ""
        attempts = 0

        async with httpx.AsyncClient(verify=self.verify_tls, timeout=settings.fortigate_timeout_s) as client:
            for attempt in range(settings.fortigate_max_retries):
                attempts = attempt + 1
                try:
                    resp = await client.request(method, url, params=params, json=json)
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last_error = self._redact(f"{type(exc).__name__}: {exc}")
                except Exception as exc:  # unexpected — redact and stop retrying
                    return SoarResult(False, self._redact(str(exc)), reference, attempts)
                else:
                    if resp.status_code in tolerate:
                        return SoarResult(True, f"FortiGate {method} {path}: {resp.status_code}",
                                          reference, attempts)
                    if resp.status_code not in _RETRYABLE_STATUS:
                        return SoarResult(False, f"FortiGate returned HTTP {resp.status_code}",
                                          reference, attempts)
                    last_error = f"HTTP {resp.status_code}"

                if attempt < settings.fortigate_max_retries - 1:
                    delay = min(settings.fortigate_backoff_cap_s,
                                settings.fortigate_backoff_base_s * (2 ** attempt))
                    await asyncio.sleep(delay + random.uniform(0, 0.25))

        return SoarResult(False, f"exhausted retries: {last_error}", reference, attempts)

    def _redact(self, text: str) -> str:
        return text.replace(self._token, "***TOKEN***") if self._token else text
