"""Heartbeat monitor — detects suspected agent compromise.

Agents ping every ``heartbeat_interval_s``. If an agent goes silent for longer
than ``interval * grace_multiplier`` *without* having acknowledged a shutdown,
its status flips to ``suspected_compromise``, an incident is opened, and an
alert is queued — anti-tampering detection: killing the agent is itself the
signal. Runs as a single async background task and only alerts on the
transition (no repeat spam).
"""

from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import Agent, Incident, Tenant
from app.services.telegram import Alert, notifier

log = logging.getLogger("autosoc.heartbeat")


class HeartbeatMonitor:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="heartbeat-monitor")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while self._running:
            await asyncio.sleep(settings.heartbeat_scan_interval_s)
            try:
                await self.scan_once()
            except Exception:
                log.exception("heartbeat scan failed")

    async def scan_once(self) -> list[str]:
        """Flip stale agents; return the ids newly flagged as compromised."""
        grace = settings.heartbeat_interval_s * settings.heartbeat_grace_multiplier
        cutoff = time.time() - grace
        flagged: list[str] = []

        async with SessionLocal() as session:
            # "isolated" is deliberately excluded: it is an operator/SOAR-
            # imposed state, not a passive liveness signal. An isolated host is
            # *expected* to eventually go quiet; that must not silently revert
            # its status to "offline" and hide that isolation was applied. It
            # only changes via an explicit rollback or a fresh heartbeat.
            rows = (await session.execute(
                select(Agent).where(Agent.status.in_(("active", "under_attack"))))).scalars().all()
            langs: dict[str, str] = {}
            for agent in rows:
                if agent.last_heartbeat >= cutoff:
                    continue
                if agent.shutdown_ack:
                    agent.status = "offline"
                    continue
                # Silent without a shutdown → suspected compromise (transition only).
                agent.status = "suspected_compromise"
                flagged.append(agent.id)
                lang = langs.get(agent.tenant_id)
                if lang is None:
                    tenant = await session.get(Tenant, agent.tenant_id)
                    lang = langs[agent.tenant_id] = (tenant.language if tenant else "en")
                session.add(Incident(
                    tenant_id=agent.tenant_id, agent_id=agent.id, severity="Critical",
                    mitre="T1562", tactic="Defense Evasion", status="open",
                    summary=f"Heartbeat lost from {agent.hostname} without shutdown — suspected compromise."))
                await notifier.enqueue(Alert(
                    chat_id=_tenant_chat(agent.tenant_id), lang=lang,
                    key="agent.suspected_compromise", params={"hostname": agent.hostname or agent.agent_uid},
                    signature=f"compromise:{agent.id}"))
            await session.commit()

        if flagged:
            log.warning("Suspected compromise flagged for %d agent(s).", len(flagged))
        return flagged


def _tenant_chat(tenant_id: str) -> str:
    # In production the chat id is resolved from the tenant's Telegram
    # credential; the demo routes to the configured default chat.
    import os

    return (os.getenv("AUTOSOC_ENT_TELEGRAM_CHAT") or tenant_id).strip()


monitor = HeartbeatMonitor()
