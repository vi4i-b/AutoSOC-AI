"""Async database engine and session management.

One async engine per process; sessions are handed to request handlers via the
:func:`get_session` dependency. On PostgreSQL the ``events`` table is promoted
to a TimescaleDB hypertable at startup (best-effort — skipped if the extension
isn't installed).
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models import Base

log = logging.getLogger("autosoc.db")

# SQLite needs check_same_thread off for the async pool; Postgres ignores it.
_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_async_engine(settings.database_url, echo=False, future=True, connect_args=_connect_args)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    if settings.is_postgres:
        await _enable_timescale()


async def _enable_timescale() -> None:
    from sqlalchemy import text

    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            await conn.execute(text(
                "SELECT create_hypertable('events', 'ts', if_not_exists => TRUE, migrate_data => TRUE)"))
        log.info("TimescaleDB hypertable ready for 'events'.")
    except Exception as exc:  # extension not present / insufficient privileges
        log.warning("TimescaleDB not enabled (falling back to a plain table): %s", exc)


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
