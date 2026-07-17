"""Test fixtures: an isolated in-file SQLite DB and an async HTTP client.

Each test run gets a fresh database and an ASGI transport client, with the OS
bootstrap and Telegram send stubbed so nothing touches the real host or network.
"""

from __future__ import annotations

import os
import tempfile

import pytest
import pytest_asyncio

# Configure the app for testing BEFORE importing it.
_TMP = tempfile.mkdtemp()
os.environ["AUTOSOC_ENT_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP}/test.db"
os.environ["AUTOSOC_ENT_JWT_SECRET"] = "test-secret-please-change-0123456789-abcdef"
os.environ.setdefault("AUTOSOC_ENT_MASTER_KEY", "")  # ephemeral AES key is fine for tests

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from app import os_bootstrap  # noqa: E402
from app.database import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services import telegram  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_os_admin(monkeypatch):
    # OS bootstrap accepts a fixed test credential; anything else is rejected.
    def fake(username, password):
        return username == "root" and password == "correct-os-pw"
    monkeypatch.setattr(os_bootstrap, "verify_os_admin", fake)
    # Also patch the reference imported into the auth router.
    import app.routers.auth as auth_router
    monkeypatch.setattr(auth_router, "verify_os_admin", fake)


@pytest.fixture(autouse=True)
def _capture_telegram(monkeypatch):
    sent = []

    async def fake_send(bot_token, chat_id, text, buttons):
        sent.append({"chat_id": chat_id, "text": text, "buttons": buttons})

    monkeypatch.setattr(telegram.notifier, "_send_func", fake_send)
    return sent


@pytest_asyncio.fixture
async def client():
    await init_db()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
