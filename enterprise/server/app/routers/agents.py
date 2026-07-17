"""Agent enrollment, heartbeat ingestion, process-tree, and isolation."""

from __future__ import annotations

import hashlib
import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import Principal, db_session, require, tenant_scope
from app.models import Agent, EnrollmentToken, Event
from app.schemas import EnrollRequest, HeartbeatRequest
from app.services.ai_analyst import analyst
from app.services.soar import run_isolation_playbook

router = APIRouter(prefix="/agents", tags=["agents"])


async def _tenant_for_enrollment(session: AsyncSession, token: str) -> str | None:
    token_hash = hashlib.sha256((token or "").encode()).hexdigest()
    row = (await session.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash))).scalars().first()
    return row.tenant_id if row else None


@router.post("/enroll", status_code=201)
async def enroll(body: EnrollRequest, session: AsyncSession = Depends(db_session)):
    """Agents authenticate with their tenant's enrollment token (no user JWT)."""
    tenant_id = await _tenant_for_enrollment(session, body.enrollment_token)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid enrollment token.")
    agent = (await session.execute(
        select(Agent).where(Agent.agent_uid == body.agent_uid))).scalars().first()
    if agent is None:
        agent = Agent(tenant_id=tenant_id, agent_uid=body.agent_uid)
        session.add(agent)
    agent.hostname = body.hostname
    agent.platform = body.platform
    agent.ip = body.ip
    agent.status = "active"
    agent.last_heartbeat = time.time()
    agent.shutdown_ack = False
    await session.commit()
    return {"agent_id": agent.id, "tenant_id": tenant_id, "heartbeat_interval_s": 5}


@router.post("/heartbeat")
async def heartbeat(body: HeartbeatRequest, session: AsyncSession = Depends(db_session)):
    """Agent ping every 5s: updates liveness, stores the process tree, runs AI."""
    agent = (await session.execute(
        select(Agent).where(Agent.agent_uid == body.agent_uid))).scalars().first()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not enrolled.")

    agent.last_heartbeat = time.time()
    if body.shutdown:
        agent.shutdown_ack = True
        agent.status = "offline"
        await session.commit()
        return {"ok": True, "status": agent.status}

    agent.shutdown_ack = False
    if agent.status in ("offline", "suspected_compromise"):
        agent.status = "active"
    if body.process_tree is not None:
        agent.process_tree = body.process_tree

    # Ingest events and run the AI analyst; escalate criticals via the playbook.
    critical_action = None
    for raw in body.events[:200]:
        message = str(raw.get("message", ""))[:2000]
        source_ip = str(raw.get("source_ip", ""))
        finding = await analyst.analyze(message)
        severity = finding.severity if finding else str(raw.get("severity", "info"))
        session.add(Event(tenant_id=agent.tenant_id, agent_id=agent.id, ts=time.time(),
                          severity=severity, mitre=finding.mitre if finding else "",
                          tactic=finding.tactic if finding else "", message=message))
        if finding and finding.is_critical and critical_action is None:
            agent.status = "under_attack"
            critical_action = await run_isolation_playbook(session, agent, finding, source_ip)

    if critical_action is None:
        await session.commit()
    return {"ok": True, "status": agent.status, "action": critical_action}


@router.get("")
async def list_agents(principal: Principal = Depends(require("agent:view")),
                      session: AsyncSession = Depends(db_session)):
    scope = tenant_scope(principal)
    query = select(Agent)
    if scope is not None:
        query = query.where(Agent.tenant_id == scope)
    agents = (await session.execute(query.order_by(Agent.enrolled_at.desc()))).scalars().all()
    return [_agent_view(a) for a in agents]


@router.get("/{agent_uid}/process_tree")
async def process_tree(agent_uid: str, principal: Principal = Depends(require("agent:process_tree")),
                       session: AsyncSession = Depends(db_session)):
    agent = await _get_scoped_agent(session, agent_uid, principal)
    return {"agent_uid": agent.agent_uid, "hostname": agent.hostname, "process_tree": agent.process_tree}


@router.post("/{agent_uid}/isolate")
async def isolate(agent_uid: str, principal: Principal = Depends(require("agent:isolate")),
                  session: AsyncSession = Depends(db_session)):
    agent = await _get_scoped_agent(session, agent_uid, principal)
    agent.isolated = True
    agent.status = "isolated"
    await session.commit()
    return {"agent_uid": agent.agent_uid, "status": agent.status, "isolated": True}


# ── helpers ───────────────────────────────────────────────────────────

async def _get_scoped_agent(session: AsyncSession, agent_uid: str, principal: Principal) -> Agent:
    agent = (await session.execute(
        select(Agent).where(Agent.agent_uid == agent_uid))).scalars().first()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found.")
    scope = tenant_scope(principal)
    if scope is not None and agent.tenant_id != scope:
        # Do not leak existence across tenants.
        raise HTTPException(status_code=404, detail="Agent not found.")
    return agent


def _agent_view(a: Agent) -> dict:
    return {
        "agent_uid": a.agent_uid, "hostname": a.hostname, "platform": a.platform,
        "ip": a.ip, "status": a.status, "isolated": a.isolated,
        "last_heartbeat": a.last_heartbeat, "tenant_id": a.tenant_id,
    }
