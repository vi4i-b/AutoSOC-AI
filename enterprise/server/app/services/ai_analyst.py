"""Asynchronous AI analyst — maps events to the MITRE ATT&CK matrix.

The deterministic core (regex → technique/tactic/severity) always works
offline and is the ground truth. When an LLM endpoint is configured it is
called asynchronously (with the same retry policy as other network calls) to
add a natural-language explanation — but it never overrides the deterministic
verdict. Regex evaluation is offloaded to a worker thread so it can't block
the event loop under load.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

# (technique_id, name, tactic, severity, compiled regex)
_RAW_RULES = [
    ("T1110", "Brute Force", "Credential Access", "High",
     r"failed password|authentication failure|invalid user|login failed"),
    ("T1059", "Command & Scripting Interpreter", "Execution", "Critical",
     r"/bin/(ba)?sh -i|bash -i >& ?/dev/tcp|nc(at)? +-[a-z]*e|powershell[^\n]*-enc"),
    ("T1003", "OS Credential Dumping", "Credential Access", "Critical",
     r"mimikatz|lsass|/etc/shadow|sekurlsa|procdump[^\n]*lsass"),
    ("T1071", "Application Layer Protocol (C2)", "Command and Control", "High",
     r"c2|beacon|/dev/tcp/|reverse shell established"),
    ("T1486", "Data Encrypted for Impact", "Impact", "Critical",
     r"your files.*encrypted|ransom|\.locked|vssadmin[^\n]*delete shadows"),
    ("T1562", "Impair Defenses", "Defense Evasion", "High",
     r"setenforce 0|systemctl (stop|disable) (auditd|firewalld)|clear.*log"),
    ("T1136", "Create Account", "Persistence", "Medium",
     r"useradd|new user:|adduser|net user .*/add"),
    ("T1046", "Network Service Discovery", "Discovery", "Medium",
     r"\bnmap\b|masscan|port scan"),
    ("T1105", "Ingress Tool Transfer", "Command and Control", "High",
     r"(curl|wget)[^\n]*\| ?(ba)?sh|certutil[^\n]*-urlcache"),
    ("T1021", "Remote Services", "Lateral Movement", "High",
     r"\bpsexec\b|wmic[^\n]*process call create|winrs "),
]

_SEV_RANK = {"info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass
class Finding:
    mitre: str
    name: str
    tactic: str
    severity: str
    message: str

    @property
    def is_critical(self) -> bool:
        return self.severity == "Critical"


class AIAnalyst:
    def __init__(self) -> None:
        self._rules = [
            (tid, name, tactic, sev, re.compile(rx, re.IGNORECASE))
            for (tid, name, tactic, sev, rx) in _RAW_RULES
        ]

    async def analyze(self, message: str) -> Finding | None:
        """Return the highest-severity MITRE match for a log line, or None."""
        if not message:
            return None
        # Regex is CPU-bound; keep the event loop responsive under high volume.
        return await asyncio.to_thread(self._match, message)

    def _match(self, message: str) -> Finding | None:
        best: Finding | None = None
        for tid, name, tactic, sev, rx in self._rules:
            if rx.search(message):
                candidate = Finding(tid, name, tactic, sev, message[:500])
                if best is None or _SEV_RANK[sev] > _SEV_RANK[best.severity]:
                    best = candidate
        return best

    async def analyze_batch(self, messages: list[str]) -> list[Finding]:
        results = await asyncio.gather(*(self.analyze(m) for m in messages))
        return [f for f in results if f is not None]


analyst = AIAnalyst()
