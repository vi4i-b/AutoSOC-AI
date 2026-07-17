"""SQLAlchemy 2.0 ORM models.

Every tenant-owned row carries ``tenant_id`` and is always queried through a
tenant filter (see :mod:`app.deps`), so company A can never read company B's
agents, events, or network map. String UUID primary keys keep the schema
portable across SQLite (dev) and PostgreSQL/TimescaleDB (prod).
"""

from __future__ import annotations

import time
import uuid

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> float:
    return time.time()


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    language: Mapped[str] = mapped_column(String(8), default="en")
    created_at: Mapped[float] = mapped_column(Float, default=_now)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    # NULL tenant = platform super-admin (all tenants).
    tenant_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("tenants.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(120), index=True)
    password_hash: Mapped[str] = mapped_column(String(255), default="")
    is_super_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[float] = mapped_column(Float, default=_now)

    __table_args__ = (Index("ix_users_tenant_username", "tenant_id", "username", unique=True),)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(32), ForeignKey("tenants.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[float] = mapped_column(Float, default=_now)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(32), ForeignKey("tenants.id"), index=True)
    agent_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(200), default="")
    platform: Mapped[str] = mapped_column(String(80), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32), default="offline")
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    last_heartbeat: Mapped[float] = mapped_column(Float, default=0.0)
    shutdown_ack: Mapped[bool] = mapped_column(Boolean, default=False)
    process_tree: Mapped[dict] = mapped_column(JSON, default=dict)
    enrolled_at: Mapped[float] = mapped_column(Float, default=_now)


class Event(Base):
    __tablename__ = "events"
    # In prod this is a TimescaleDB hypertable partitioned on ``ts``.
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[float] = mapped_column(Float, default=_now, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    mitre: Mapped[str] = mapped_column(String(32), default="")
    tactic: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(Text, default="")


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[str] = mapped_column(String(32), default="")
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    mitre: Mapped[str] = mapped_column(String(32), default="")
    tactic: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(24), default="open")
    summary: Mapped[str] = mapped_column(Text, default="")
    fortigate_ref: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[float] = mapped_column(Float, default=_now)


class NetworkEdge(Base):
    __tablename__ = "network_edges"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    src_agent_id: Mapped[str] = mapped_column(String(32))
    dst_label: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(40), default="connection")


class ApiCredential(Base):
    __tablename__ = "api_credentials"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(40))         # fortigate | telegram
    host: Mapped[str] = mapped_column(String(255), default="")
    encrypted: Mapped[str] = mapped_column(Text)           # AES-256-GCM blob
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=_now)
