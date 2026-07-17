"""Runtime configuration for the AutoSOC enterprise server.

Every secret and tuning knob comes from the environment so the same image
runs in dev (SQLite) and prod (PostgreSQL/TimescaleDB) without code changes.
Sensible defaults let it boot out-of-the-box for a demo; production is
expected to set the secrets explicitly (a warning is logged otherwise).
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from dataclasses import dataclass, field

log = logging.getLogger("autosoc.config")


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


@dataclass(frozen=True)
class Settings:
    # ── Database ──────────────────────────────────────────────────────
    # Dev default: local async SQLite. Prod: set to
    #   postgresql+asyncpg://user:pass@host:5432/autosoc
    database_url: str = field(default_factory=lambda: _env(
        "AUTOSOC_ENT_DATABASE_URL", "sqlite+aiosqlite:///./autosoc_ent.db"))

    # ── Auth / crypto ────────────────────────────────────────────────
    jwt_secret: str = field(default_factory=lambda: _env("AUTOSOC_ENT_JWT_SECRET"))
    jwt_algorithm: str = "HS256"
    access_token_ttl_min: int = field(default_factory=lambda: int(_env("AUTOSOC_ENT_TOKEN_TTL_MIN", "60")))
    # 32-byte AES-256 key, base64-encoded, for encrypting stored API keys.
    master_key_b64: str = field(default_factory=lambda: _env("AUTOSOC_ENT_MASTER_KEY"))

    # PAM service used to verify the OS super-admin password on Linux.
    pam_service: str = field(default_factory=lambda: _env("AUTOSOC_ENT_PAM_SERVICE", "login"))

    # ── Agent / monitoring ───────────────────────────────────────────
    heartbeat_interval_s: int = 5
    # Missed pings before an agent is flagged as a suspected compromise.
    heartbeat_grace_multiplier: int = 3
    heartbeat_scan_interval_s: int = 3

    # ── Telegram ─────────────────────────────────────────────────────
    telegram_bot_token: str = field(default_factory=lambda: _env("AUTOSOC_ENT_TELEGRAM_TOKEN"))
    telegram_aggregate_window_s: float = 5.0
    telegram_min_send_interval_s: float = 1.0

    # ── FortiGate SOAR ───────────────────────────────────────────────
    fortigate_max_retries: int = 4
    fortigate_backoff_base_s: float = 0.5
    fortigate_backoff_cap_s: float = 8.0
    fortigate_timeout_s: float = 12.0
    fortigate_verify_tls: bool = field(default_factory=lambda: _env("AUTOSOC_ENT_FGT_VERIFY_TLS", "1") != "0")

    default_language: str = field(default_factory=lambda: _env("AUTOSOC_ENT_LANG", "en"))

    def resolved_jwt_secret(self) -> str:
        if self.jwt_secret:
            return self.jwt_secret
        log.warning("AUTOSOC_ENT_JWT_SECRET is not set — using an ephemeral secret. "
                    "Tokens will not survive a restart. Set it in production.")
        return _EPHEMERAL_JWT

    def resolved_master_key(self) -> bytes:
        if self.master_key_b64:
            key = base64.b64decode(self.master_key_b64)
            if len(key) != 32:
                raise ValueError("AUTOSOC_ENT_MASTER_KEY must decode to exactly 32 bytes (AES-256).")
            return key
        log.warning("AUTOSOC_ENT_MASTER_KEY is not set — using an ephemeral AES key. "
                    "Encrypted secrets will not survive a restart. Set it in production.")
        return _EPHEMERAL_MASTER

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith("postgresql")


# Ephemeral fallbacks generated once per process (dev only).
_EPHEMERAL_JWT = secrets.token_urlsafe(48)
_EPHEMERAL_MASTER = secrets.token_bytes(32)

settings = Settings()
