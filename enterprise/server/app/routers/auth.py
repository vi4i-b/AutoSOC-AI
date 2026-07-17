"""Authentication & user administration.

Stage 1 (bootstrap): OS admin password → super-admin JWT (all permissions).
Stage 2: super-admin creates tenants and employees with granular permissions;
employees log in for a scoped JWT.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import Principal, db_session, get_principal, require
from app.models import EnrollmentToken, Tenant, User
from app.os_bootstrap import verify_os_admin
from app.permissions import PERMISSIONS, ROLE_TEMPLATES, sanitize
from app.schemas import (BootstrapRequest, CreateTenantRequest, CreateUserRequest,
                         LoginRequest, TokenResponse)
from app.security import create_access_token, hash_password, verify_password
import secrets

router = APIRouter(prefix="/auth", tags=["auth"])

_SUPER_USERNAME_PREFIX = "os:"


@router.post("/bootstrap", response_model=TokenResponse)
async def bootstrap(body: BootstrapRequest, session: AsyncSession = Depends(db_session)):
    """Prove control of the host with OS admin credentials → super-admin token."""
    if not verify_os_admin(body.os_username, body.os_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="OS administrator authentication failed.")

    username = _SUPER_USERNAME_PREFIX + body.os_username
    user = (await session.execute(
        select(User).where(User.username == username, User.is_super_admin.is_(True)))).scalars().first()
    if user is None:
        user = User(tenant_id=None, username=username, password_hash="",
                    is_super_admin=True, permissions=list(PERMISSIONS), active=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

    token = create_access_token(user_id=user.id, tenant_id=None, super_admin=True,
                                permissions=list(PERMISSIONS))
    return TokenResponse(access_token=token, super_admin=True, permissions=list(PERMISSIONS))


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, session: AsyncSession = Depends(db_session)):
    query = select(User).where(User.username == body.username, User.active.is_(True))
    if body.tenant_id:
        query = query.where(User.tenant_id == body.tenant_id)
    user = (await session.execute(query)).scalars().first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password.")
    perms = list(PERMISSIONS) if user.is_super_admin else sanitize(user.permissions)
    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id,
                                super_admin=user.is_super_admin, permissions=perms)
    return TokenResponse(access_token=token, super_admin=user.is_super_admin,
                         permissions=perms, tenant_id=user.tenant_id)


@router.get("/me")
async def me(principal: Principal = Depends(get_principal)):
    return {
        "user_id": principal.user_id,
        "super_admin": principal.is_super_admin,
        "tenant_id": principal.token_tenant,
        "effective_tenant": principal.effective_tenant,
        "permissions": sorted(principal.permissions) if not principal.is_super_admin else sorted(PERMISSIONS),
    }


@router.get("/permissions")
async def permission_catalog(_: Principal = Depends(get_principal)):
    return {"permissions": PERMISSIONS, "role_templates": ROLE_TEMPLATES}


@router.post("/tenants", status_code=201)
async def create_tenant(body: CreateTenantRequest, principal: Principal = Depends(require("tenant:manage")),
                        session: AsyncSession = Depends(db_session)):
    if (await session.execute(select(Tenant).where(Tenant.name == body.name))).scalars().first():
        raise HTTPException(status_code=409, detail="Tenant name already exists.")
    tenant = Tenant(name=body.name, language=body.language)
    session.add(tenant)
    await session.flush()
    # Issue an enrollment token so agents can join this tenant.
    raw = "enr-" + secrets.token_urlsafe(18)
    session.add(EnrollmentToken(tenant_id=tenant.id,
                                token_hash=hashlib.sha256(raw.encode()).hexdigest()))
    await session.commit()
    return {"tenant_id": tenant.id, "name": tenant.name, "enrollment_token": raw}


@router.post("/users", status_code=201)
async def create_user(body: CreateUserRequest, principal: Principal = Depends(require("user:manage")),
                      session: AsyncSession = Depends(db_session)):
    # Employees can only be created inside a tenant the caller controls.
    if not principal.is_super_admin and body.tenant_id != principal.token_tenant:
        raise HTTPException(status_code=403, detail="Cannot create users in another tenant.")
    if (await session.get(Tenant, body.tenant_id)) is None:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    exists = (await session.execute(select(User).where(
        User.tenant_id == body.tenant_id, User.username == body.username))).scalars().first()
    if exists:
        raise HTTPException(status_code=409, detail="Username already exists in this tenant.")
    user = User(tenant_id=body.tenant_id, username=body.username,
                password_hash=hash_password(body.password), is_super_admin=False,
                permissions=sanitize(body.permissions), active=True)
    session.add(user)
    await session.commit()
    return {"user_id": user.id, "username": user.username, "permissions": user.permissions}
