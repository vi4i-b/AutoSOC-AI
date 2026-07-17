"""Pydantic request/response models."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ── auth ──────────────────────────────────────────────────────────────

class BootstrapRequest(BaseModel):
    os_username: str
    os_password: str


class LoginRequest(BaseModel):
    username: str
    password: str
    tenant_id: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    super_admin: bool
    permissions: list[str]
    tenant_id: str | None = None


class CreateUserRequest(BaseModel):
    tenant_id: str
    username: str
    password: str = Field(min_length=8)
    permissions: list[str] = Field(default_factory=list)


class CreateTenantRequest(BaseModel):
    name: str
    language: str = "en"


# ── agents ────────────────────────────────────────────────────────────

class EnrollRequest(BaseModel):
    enrollment_token: str
    agent_uid: str
    hostname: str = ""
    platform: str = ""
    ip: str = ""


class HeartbeatRequest(BaseModel):
    agent_uid: str
    status: str = "active"
    shutdown: bool = False
    process_tree: dict | None = None
    events: list[dict] = Field(default_factory=list)


class NodeActionRequest(BaseModel):
    action: str  # isolate | rollback | ask_ai


class CommandResultRequest(BaseModel):
    ok: bool
    detail: str = ""


# ── credentials / integrations ───────────────────────────────────────

class CredentialRequest(BaseModel):
    kind: str          # fortigate | telegram
    host: str = ""
    api_key: str
    meta: dict = Field(default_factory=dict)
