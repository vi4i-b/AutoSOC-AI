"""Interactive network topology map (Cytoscape-ready JSON) + real-time stream.

The map is always tenant-scoped. Each node reports a live status (active,
under_attack, isolated, offline, suspected_compromise) and the context actions
the *current* token is allowed to invoke — so the React UI only ever offers
buttons the user can actually use.
"""

from __future__ import annotations

import asyncio
import contextlib

import jwt
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import SessionLocal
from app.deps import Principal, db_session, get_principal, require, tenant_scope
from app.models import Agent, AgentCommand, NetworkEdge, Tenant
from app.schemas import NodeActionRequest
from app.security import decode_access_token

router = APIRouter(prefix="/network", tags=["network"])


def _actions_for(principal: Principal) -> list[str]:
    actions = []
    if principal.has("network:isolate") or principal.has("agent:isolate"):
        actions.append("isolate")
    if principal.has("agent:process_tree"):
        actions.append("process_tree")
    if principal.has("ai:query"):
        actions.append("ask_ai")
    if principal.has("incident:respond"):
        actions.append("rollback")
    return actions


async def _build_map(session: AsyncSession, tenant_id: str | None, actions: list[str]) -> dict:
    query = select(Agent)
    if tenant_id is not None:
        query = query.where(Agent.tenant_id == tenant_id)
    agents = (await session.execute(query)).scalars().all()

    tenant_name = "All tenants"
    if tenant_id is not None:
        tenant = await session.get(Tenant, tenant_id)
        tenant_name = tenant.name if tenant else tenant_id

    nodes = [{"data": {"id": "gateway", "label": tenant_name, "type": "gateway", "status": "active"}}]
    edges = [{"data": {"id": "agent-list", "source": "gateway", "target": "gateway"}}] if not agents else []

    for a in agents:
        nodes.append({"data": {
            "id": a.agent_uid, "label": a.hostname or a.agent_uid, "type": "host",
            "status": a.status, "platform": a.platform, "ip": a.ip,
            "isolated": a.isolated, "actions": actions,
        }})
        edges.append({"data": {"id": f"e-{a.agent_uid}", "source": "gateway",
                               "target": a.agent_uid, "kind": "uplink"}})

    if tenant_id is not None:
        extra = (await session.execute(
            select(NetworkEdge).where(NetworkEdge.tenant_id == tenant_id))).scalars().all()
        for e in extra:
            edges.append({"data": {"id": e.id, "source": e.src_agent_id,
                                   "target": e.dst_label, "kind": e.kind}})

    return {"nodes": nodes, "edges": edges, "available_actions": actions}


@router.get("/map")
async def network_map(principal: Principal = Depends(require("network:view")),
                      session: AsyncSession = Depends(db_session)):
    return await _build_map(session, tenant_scope(principal), _actions_for(principal))


@router.post("/nodes/{agent_uid}/action")
async def node_action(agent_uid: str, body: NodeActionRequest,
                      principal: Principal = Depends(get_principal),
                      session: AsyncSession = Depends(db_session)):
    scope = tenant_scope(principal)
    agent = (await session.execute(
        select(Agent).where(Agent.agent_uid == agent_uid))).scalars().first()
    if agent is None or (scope is not None and agent.tenant_id != scope):
        raise HTTPException(status_code=404, detail="Node not found.")

    if body.action == "isolate":
        if not (principal.has("network:isolate") or principal.has("agent:isolate")):
            raise HTTPException(status_code=403, detail="Permission 'network:isolate' required.")
        agent.isolated = True
        agent.status = "isolated"
        # A prior clean shutdown may have left shutdown_ack=True; if we don't
        # clear it, the heartbeat monitor's staleness sweep (services/heartbeat.py)
        # silently flips status back to "offline" a few seconds later, even
        # though `isolated` stays True — misleading the analyst's map view.
        agent.shutdown_ack = False
        # Queue the enforcement command so the agent applies it locally on its
        # next check-in (see routers/agents.py poll_commands / main.cpp).
        session.add(AgentCommand(agent_id=agent.id, command="isolate", status="pending"))
        await session.commit()
        return {"agent_uid": agent_uid, "status": agent.status}

    if body.action == "rollback":
        if not principal.has("incident:respond"):
            raise HTTPException(status_code=403, detail="Permission 'incident:respond' required.")
        agent.isolated = False
        agent.status = "active"
        agent.shutdown_ack = False
        session.add(AgentCommand(agent_id=agent.id, command="release", status="pending"))
        await session.commit()
        return {"agent_uid": agent_uid, "status": agent.status}

    if body.action == "process_tree":
        if not principal.has("agent:process_tree"):
            raise HTTPException(status_code=403, detail="Permission 'agent:process_tree' required.")
        return {"agent_uid": agent_uid, "process_tree": agent.process_tree}

    raise HTTPException(status_code=400, detail=f"Unsupported action '{body.action}'.")


@router.websocket("/stream")
async def network_stream(ws: WebSocket):
    """Real-time map: authenticates via ?token=, pushes a snapshot every 2s."""
    token = ws.query_params.get("token", "")
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError:
        await ws.close(code=4401)
        return
    if not (claims.get("sa") or "network:view" in claims.get("perms", [])):
        await ws.close(code=4403)
        return

    tenant_id = ws.query_params.get("tenant") or claims.get("tenant")
    if not claims.get("sa"):
        tenant_id = claims.get("tenant")
    actions = _actions_for(Principal(
        user_id=claims.get("sub", ""), is_super_admin=bool(claims.get("sa")),
        permissions=frozenset(claims.get("perms", [])), token_tenant=claims.get("tenant"),
        effective_tenant=tenant_id))

    await ws.accept()
    try:
        while True:
            async with SessionLocal() as session:
                snapshot = await _build_map(session, tenant_id, actions)
            await ws.send_json(snapshot)
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        return
    except Exception:
        with contextlib.suppress(Exception):
            await ws.close()
