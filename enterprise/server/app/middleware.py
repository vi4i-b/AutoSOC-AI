"""Per-request tenant context and JWT validation middleware.

Every request's bearer token is decoded once here and turned into a
:class:`app.deps.Principal` on ``request.state``. Tenant isolation is enforced
at this layer: an employee token may only ever act on its own tenant, and a
cross-tenant ``X-Tenant-ID`` is rejected outright. A super-admin may target a
specific tenant via ``X-Tenant-ID`` or operate across all of them.
"""

from __future__ import annotations

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.deps import Principal
from app.i18n import normalize
from app.security import decode_access_token


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.principal = None
        language = normalize(request.headers.get("X-Lang") or request.headers.get("Accept-Language"))

        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            try:
                claims = decode_access_token(token)
            except jwt.PyJWTError:
                claims = None
            if claims:
                token_tenant = claims.get("tenant")
                is_sa = bool(claims.get("sa"))
                requested_tenant = request.headers.get("X-Tenant-ID")

                if is_sa:
                    effective = requested_tenant or None
                else:
                    if requested_tenant and requested_tenant != token_tenant:
                        return JSONResponse(
                            {"detail": "Cross-tenant access denied."}, status_code=403)
                    effective = token_tenant

                request.state.principal = Principal(
                    user_id=claims.get("sub", ""),
                    is_super_admin=is_sa,
                    permissions=frozenset(claims.get("perms", [])),
                    token_tenant=token_tenant,
                    effective_tenant=effective,
                    jti=claims.get("jti", ""),
                    language=language,
                )

        return await call_next(request)
