"""AutoSOC enterprise SOAR/EDR API server (FastAPI, fully async).

Wires the two-stage auth, multi-tenant middleware, agent ingestion, network
map, AI analyst, and SOAR playbooks into one ASGI app. Background services
(heartbeat monitor, Telegram aggregator) start with the app lifespan.
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.database import SessionLocal, init_db
from app.middleware import TenantContextMiddleware
from app.routers import agents, auth, incidents, integrations, network
from app.services.heartbeat import monitor
from app.services.soar import rollback_incident
from app.services.telegram import notifier

logging.basicConfig(level=os.getenv("AUTOSOC_ENT_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("autosoc.main")


async def _lifespan(app: FastAPI):
    await init_db()
    await notifier.start()
    await monitor.start()
    log.info("AutoSOC enterprise server started.")
    try:
        yield
    finally:
        await monitor.stop()
        await notifier.stop()
        log.info("AutoSOC enterprise server stopped.")


app = FastAPI(title="AutoSOC Enterprise SOAR/EDR", version="1.0.0", lifespan=_lifespan)

# Multi-tenant JWT context runs before every request.
app.add_middleware(TenantContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=(os.getenv("AUTOSOC_ENT_CORS_ORIGINS", "*").split(",")),
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(network.router)
app.include_router(incidents.router)
app.include_router(integrations.router)

_root = APIRouter()


@_root.get("/health")
async def health():
    return {"status": "ok", "service": "autosoc-enterprise"}


@_root.get("/")
async def root():
    return {"service": "AutoSOC Enterprise SOAR/EDR", "version": "1.0.0",
            "docs": "/docs", "health": "/health"}


@_root.post("/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request):
    """Handles the inline 'Rollback' button. The path secret gates the webhook."""
    expected = os.getenv("AUTOSOC_ENT_TELEGRAM_WEBHOOK_SECRET", "")
    if not expected or secret != expected:
        return {"ok": False}
    update = await request.json()
    callback = update.get("callback_query") or {}
    data = callback.get("data", "")
    if data.startswith("rollback:"):
        incident_id = data.split(":", 1)[1]
        from app.models import Incident

        async with SessionLocal() as session:
            incident = await session.get(Incident, incident_id)
            if incident is not None:
                await rollback_incident(session, incident)
    return {"ok": True}


app.include_router(_root)
