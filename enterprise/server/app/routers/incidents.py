"""Incidents, the AI analyst query endpoint, and one-click rollback."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import Principal, db_session, require, tenant_scope
from app.models import Incident
from app.services.ai_analyst import analyst
from app.services.soar import rollback_incident

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
async def list_incidents(principal: Principal = Depends(require("incident:view")),
                         session: AsyncSession = Depends(db_session)):
    scope = tenant_scope(principal)
    query = select(Incident)
    if scope is not None:
        query = query.where(Incident.tenant_id == scope)
    rows = (await session.execute(query.order_by(Incident.created_at.desc()).limit(200))).scalars().all()
    return [{
        "id": i.id, "tenant_id": i.tenant_id, "agent_id": i.agent_id, "severity": i.severity,
        "mitre": i.mitre, "tactic": i.tactic, "status": i.status, "summary": i.summary,
        "fortigate_ref": i.fortigate_ref, "created_at": i.created_at,
    } for i in rows]


@router.post("/incidents/{incident_id}/rollback")
async def rollback(incident_id: str, principal: Principal = Depends(require("incident:respond")),
                   session: AsyncSession = Depends(db_session)):
    scope = tenant_scope(principal)
    incident = await session.get(Incident, incident_id)
    if incident is None or (scope is not None and incident.tenant_id != scope):
        raise HTTPException(status_code=404, detail="Incident not found.")
    return await rollback_incident(session, incident)


@router.post("/ai/query")
async def ai_query(message: str = Body(..., embed=True),
                   principal: Principal = Depends(require("ai:query"))):
    finding = await analyst.analyze(message)
    if finding is None:
        return {"matched": False, "detail": "No MITRE ATT&CK technique matched."}
    return {
        "matched": True, "mitre": finding.mitre, "name": finding.name,
        "tactic": finding.tactic, "severity": finding.severity,
    }
