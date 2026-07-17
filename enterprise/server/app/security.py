"""Cryptographic primitives: password hashing, JWT, and AES-256 secret storage.

- Passwords: PBKDF2-HMAC-SHA256 with a per-password random salt, constant-time
  verification.
- JWT: HS256 access tokens carrying tenant + granular permissions.
- Secrets at rest (FortiGate/Telegram keys): AES-256-GCM (authenticated
  encryption) with the platform master key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

_PBKDF2_ITERATIONS = 260_000


# ── passwords ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, digest_b64 = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


# ── JWT ───────────────────────────────────────────────────────────────

def create_access_token(*, user_id: str, tenant_id: str | None, super_admin: bool,
                        permissions: list[str], ttl_min: int | None = None) -> str:
    now = int(time.time())
    ttl = (ttl_min if ttl_min is not None else settings.access_token_ttl_min) * 60
    payload = {
        "sub": user_id,
        "tenant": tenant_id,
        "sa": super_admin,
        "perms": permissions,
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.resolved_jwt_secret(), algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on any invalid/expired token."""
    return jwt.decode(token, settings.resolved_jwt_secret(), algorithms=[settings.jwt_algorithm])


# ── AES-256-GCM secret storage ────────────────────────────────────────

def encrypt_secret(plaintext: str) -> str:
    """Return base64(nonce || ciphertext||tag). Authenticated (AES-256-GCM)."""
    aes = AESGCM(settings.resolved_master_key())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_secret(blob: str) -> str:
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(settings.resolved_master_key())
    return aes.decrypt(nonce, ct, None).decode("utf-8")
