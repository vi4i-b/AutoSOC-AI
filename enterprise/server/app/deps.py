"""Request principal, RBAC, and tenant-scoping dependencies.

The :class:`Principal` is built by :class:`app.middleware.TenantContextMiddleware`
from the JWT and attached to ``request.state``. Handlers pull it via
:func:`get_principal`, gate themselves with :func:`require`, and scope every
query with :func:`tenant_scope` so cross-tenant reads are structurally
impossible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session


@dataclass
class Principal:
    user_id: str
    is_super_admin: bool
    permissions: frozenset[str]
    token_tenant: str | None            # tenant the token belongs to (None for super-admin)
    effective_tenant: str | None        # tenant the request operates on (None = all, super-admin only)
    jti: str = ""
    language: str = "en"
    _extra: dict = field(default_factory=dict)

    def has(self, permission: str) -> bool:
        return self.is_super_admin or permission in self.permissions


def get_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing or invalid authentication token.")
    return principal


def require(permission: str):
    """Dependency factory: allow the request only if the principal holds ``permission``."""

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Permission '{permission}' is required.")
        return principal

    return _dep


def tenant_scope(principal: Principal) -> str | None:
    """The tenant id to filter queries by (None means unrestricted — super-admin)."""
    if principal.is_super_admin:
        return principal.effective_tenant  # may be None (all tenants) or a chosen one
    return principal.token_tenant


def require_tenant(principal: Principal = Depends(get_principal)) -> str:
    """Resolve a concrete tenant id, or 400 if a super-admin didn't pick one."""
    scope = tenant_scope(principal)
    if scope is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Select a tenant via the X-Tenant-ID header.")
    return scope


# Re-export the session dependency for convenient imports in routers.
async def db_session() -> AsyncSession:
    async for session in get_session():
        yield session
