"""SOAR playbook orchestration.

The automated critical-incident response:

    AI detects critical  →  agent isolates the host locally
                         →  server calls FortiGate (retry policy)
                         →  interactive Telegram report with a Rollback button

Integration secrets (FortiGate token, Telegram bot token) are stored per tenant
encrypted with AES-256 and decrypted here only in memory.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Agent, ApiCredential, Incident, Tenant
from app.security import decrypt_secret
from app.services.ai_analyst import Finding
from app.services.fortigate import FortiGateClient
from app.services.heartbeat import _tenant_chat
from app.services.telegram import Alert, notifier

log = logging.getLogger("autosoc.soar")


async def _load_credential(session: AsyncSession, tenant_id: str, kind: str) -> ApiCredential | None:
    return (await session.execute(
        select(ApiCredential).where(ApiCredential.tenant_id == tenant_id, ApiCredential.kind == kind)
    )).scalars().first()


async def load_fortigate(session: AsyncSession, tenant_id: str) -> FortiGateClient | None:
    cred = await _load_credential(session, tenant_id, "fortigate")
    if not cred:
        return None
    token = decrypt_secret(cred.encrypted)
    meta = cred.meta or {}
    return FortiGateClient(cred.host, token, vdom=meta.get("vdom", "root"),
                           address_group=meta.get("group", "AutoSOC_Blocklist"))


async def _tenant_lang(session: AsyncSession, tenant_id: str) -> str:
    tenant = await session.get(Tenant, tenant_id)
    return tenant.language if tenant else "en"


async def run_isolation_playbook(session: AsyncSession, agent: Agent, finding: Finding,
                                 source_ip: str = "") -> dict:
    """Isolate + block + notify. Returns a structured result for the API/logs."""
    lang = await _tenant_lang(session, agent.tenant_id)

    # 1) Local isolation (agent enforces it on its next poll; status reflects it now).
    agent.isolated = True
    agent.status = "isolated"

    # 2) Open the incident record.
    incident = Incident(
        tenant_id=agent.tenant_id, agent_id=agent.id, severity=finding.severity,
        mitre=finding.mitre, tactic=finding.tactic, status="contained",
        summary=f"{finding.name} on {agent.hostname}: {finding.message}")
    session.add(incident)
    await session.flush()  # get incident.id

    # 3) FortiGate SOAR with retry (best-effort; failure doesn't block isolation).
    fgt_result = None
    if source_ip:
        client = await load_fortigate(session, agent.tenant_id)
        if client is not None:
            result = await client.block_ip(source_ip, comment=f"AutoSOC {finding.mitre}")
            fgt_result = {"ok": result.ok, "attempts": result.attempts, "message": result.message}
            if result.ok:
                incident.fortigate_ref = result.reference

    await session.commit()

    # 4) Interactive Telegram report with a Rollback button.
    await notifier.enqueue(Alert(
        chat_id=_tenant_chat(agent.tenant_id), lang=lang, key="incident.critical",
        params={"hostname": agent.hostname or agent.agent_uid,
                "technique": finding.name, "tactic": finding.tactic},
        signature=f"incident:{agent.id}:{finding.mitre}",
        rollback_incident=incident.id,
        bot_token=await _telegram_token(session, agent.tenant_id)))

    log.warning("SOAR playbook executed for agent %s (%s).", agent.agent_uid, finding.mitre)
    return {"incident_id": incident.id, "isolated": True, "fortigate": fgt_result}


async def rollback_incident(session: AsyncSession, incident: Incident) -> dict:
    """Undo an automated response: un-isolate the host and unblock the IP."""
    agent = (await session.execute(
        select(Agent).where(Agent.id == incident.agent_id))).scalars().first()
    fgt = None
    if agent:
        agent.isolated = False
        agent.status = "active"
    if incident.fortigate_ref:
        client = await load_fortigate(session, incident.tenant_id)
        if client is not None:
            ip = incident.fortigate_ref.replace("AutoSOC_", "")
            result = await client.unblock_ip(ip)
            fgt = {"ok": result.ok, "message": result.message}
    incident.status = "rolled_back"
    await session.commit()

    if agent:
        await notifier.enqueue(Alert(
            chat_id=_tenant_chat(incident.tenant_id),
            lang=await _tenant_lang(session, incident.tenant_id),
            key="agent.rollback", params={"hostname": agent.hostname or agent.agent_uid},
            signature=f"rollback:{incident.id}",
            bot_token=await _telegram_token(session, incident.tenant_id)))
    return {"rolled_back": True, "fortigate": fgt}


async def _telegram_token(session: AsyncSession, tenant_id: str) -> str:
    cred = await _load_credential(session, tenant_id, "telegram")
    return decrypt_secret(cred.encrypted) if cred else ""
