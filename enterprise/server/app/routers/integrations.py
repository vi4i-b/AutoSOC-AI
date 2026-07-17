"""Integration credentials — FortiGate / Telegram API keys, AES-256 at rest."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import Principal, db_session, require, require_tenant
from app.models import ApiCredential
from app.schemas import CredentialRequest
from app.security import encrypt_secret

router = APIRouter(prefix="/integrations", tags=["integrations"])

_KINDS = {"fortigate", "telegram"}


@router.post("/credentials", status_code=201)
async def upsert_credential(body: CredentialRequest,
                            principal: Principal = Depends(require("settings:manage")),
                            session: AsyncSession = Depends(db_session)):
    if body.kind not in _KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {sorted(_KINDS)}")
    tenant_id = require_tenant(principal)
    cred = (await session.execute(select(ApiCredential).where(
        ApiCredential.tenant_id == tenant_id, ApiCredential.kind == body.kind))).scalars().first()
    if cred is None:
        cred = ApiCredential(tenant_id=tenant_id, kind=body.kind)
        session.add(cred)
    cred.host = body.host
    cred.meta = body.meta
    cred.encrypted = encrypt_secret(body.api_key)  # AES-256-GCM
    await session.commit()
    return {"kind": body.kind, "host": body.host, "stored": True}


@router.get("/credentials")
async def list_credentials(principal: Principal = Depends(require("settings:manage")),
                           session: AsyncSession = Depends(db_session)):
    tenant_id = require_tenant(principal)
    rows = (await session.execute(select(ApiCredential).where(
        ApiCredential.tenant_id == tenant_id))).scalars().all()
    # Secrets are never returned — only that they exist.
    return [{"kind": c.kind, "host": c.host, "configured": True, "created_at": c.created_at}
            for c in rows]
