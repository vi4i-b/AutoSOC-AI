# AutoSOC — Compliance & standards mapping

> **Read this framing first.** Software does not "get certified" — *organizations*
> do. A product's role is to provide the **technical controls and audit evidence**
> that make an organization's ISO 27001 / SOC 2 / PCI-DSS / etc. assessment
> pass. This document maps AutoSOC's features to the specific control clauses
> they support, honestly marking what AutoSOC **provides**, what it **helps
> evidence**, and what remains the **operator's responsibility**.

Legend: ✅ control implemented in AutoSOC · 🧾 produces audit evidence ·
👤 operator/organizational responsibility · 🗺️ roadmap.

---

## Standards covered

| Framework | Scope | Relevance to AutoSOC |
|-----------|-------|----------------------|
| **ISO/IEC 27001:2022** | ISMS + Annex A controls | Logging, access control, monitoring, response |
| **SOC 2 (AICPA TSC)** | Security/Availability/Confidentiality | Access control, monitoring, incident response, change |
| **NIST CSF 2.0** | Identify/Protect/Detect/Respond/Recover | AutoSOC is largely a *Detect + Respond* tool |
| **NIST SP 800-53 Rev.5** | Federal control catalog | AU (audit), AC (access), IR (incident), SI (integrity) |
| **PCI-DSS 4.0** | Cardholder data environments | Req.10 (logging), Req.8 (access), Req.11 (monitoring) |
| **GDPR** | EU personal-data protection | Data minimization, retention, access, breach detection |

---

## 1. Access control & authentication

| Control | ISO 27001 | SOC 2 | PCI-DSS | AutoSOC capability | Status |
|---------|-----------|-------|---------|--------------------|--------|
| Unique user identity | A.5.16 | CC6.1 | 8.2 | Per-user accounts; no shared logins | ✅ |
| Role-based least privilege | A.5.15 | CC6.3 | 7.2 | `permissions.py`: viewer < analyst < responder < admin, enforced via `can()`/`require()` | ✅ |
| Restricted registration | A.5.16 | CC6.2 | 8.1 | Invite-only / closed registration modes (`AUTOSOC_REGISTRATION_MODE`) | ✅ |
| Strong password policy | A.5.17 | CC6.1 | 8.3 | Length/complexity policy in `validators.py` | ✅ |
| Brute-force lockout | A.8.5 | CC6.1 | 8.3.4 | Failed-login lockout with backoff | ✅ |
| OS-level admin binding | A.5.15 | CC6.1 | 7.1 | Linux PAM authentication for the local operator | ✅ |
| Two-stage / Zero-Trust RBAC | A.5.15 | CC6.3 | 7.2 | Enterprise stack: OS-bootstrap → scoped JWT | ✅ (enterprise) |
| MFA | A.8.5 | CC6.1 | 8.4 | Telegram second-factor for account link | ◐ partial |

## 2. Logging & audit trail

| Control | ISO 27001 | 800-53 | PCI-DSS | AutoSOC capability | Status |
|---------|-----------|--------|---------|--------------------|--------|
| Event logging | A.8.15 | AU-2 | 10.2 | Central log ingestion (agent + syslog); `security_events`, `audit_events` | ✅ 🧾 |
| Audit of admin actions | A.8.15 | AU-2 | 10.2.1 | `add_audit_event` on every privileged action (isolate, role change, token regen, key change…) | ✅ 🧾 |
| **Log integrity / tamper-evidence** | A.8.15 | AU-9 | 10.5 | **Hash-chained audit log**: each entry hashes the previous; `verify_audit_chain()` detects any edit/deletion | ✅ 🧾 |
| Log export for review | A.8.15 | AU-6 | 10.6 | `export_audit_log()` → CSV; Admin dialog "Export CSV" | ✅ 🧾 |
| Time-stamped records | A.8.15 | AU-8 | 10.4 | Every record carries `created_at` | ✅ |
| Log retention | A.8.15 | AU-11 | 10.5.1 | Configurable retention + `purge_logs_older_than()` | ✅ |
| Central log forwarding to SIEM | A.8.15 | AU-6 | 10.5.4 | Log Destination → syslog/SIEM + file archive | ✅ |

> The tamper-evident chain and export together satisfy the intent of PCI-DSS
> 10.5 ("secure audit trails so they cannot be altered") and 800-53 AU-9
> ("protection of audit information") at the application layer.

## 3. Monitoring, detection & threat management

| Control | ISO 27001 | NIST CSF | PCI-DSS | AutoSOC capability | Status |
|---------|-----------|----------|---------|--------------------|--------|
| Continuous monitoring | A.8.16 | DE.CM | 10.4 | Agent heartbeat + telemetry; syslog receiver | ✅ |
| Intrusion detection | A.8.16 | DE.CM-1 | 11.5 | Detection-rule engine (~35 ATT&CK-mapped rules) on logs + telemetry | ✅ |
| Malware / IOC detection | A.8.7 | DE.CM-4 | 5.x | IOC watchlist + threat-intel enrichment (VT/AbuseIPDB/OTX) | ✅ |
| Anomaly / hidden-service detection | A.8.16 | DE.AE | 11.5 | nmap scan vs agent-reported listeners | ✅ |
| File integrity monitoring | A.8.9 | PR.DS-6 | 11.5 | Endpoint agent (hand-off to Wazuh/Sysmon for deep FIM) | ◐ partial |
| Threat intelligence | A.5.7 | ID.RA | — | Enrichment across VirusTotal / AbuseIPDB / OTX | ✅ |

## 4. Incident response

| Control | ISO 27001 | 800-53 | NIST CSF | AutoSOC capability | Status |
|---------|-----------|--------|----------|--------------------|--------|
| Incident management process | A.5.24 | IR-1 | RS.MA | Incident cases: status/severity/notes | ✅ 🧾 |
| Response & containment | A.5.26 | IR-4 | RS.MI | Endpoint isolation (iptables/netsh) + firewall block playbooks | ✅ |
| Automated response | A.5.26 | IR-4(1) | RS.MI | SOAR playbook: detect → isolate → block → notify, with rollback | ✅ |
| Notification / escalation | A.6.8 | IR-6 | RS.CO | Telegram alerting (High/Critical) | ✅ |
| Recovery | A.5.29 | IR-4 | RC.RP | Isolation rollback / release | ✅ |

## 5. Data protection & privacy (incl. GDPR)

| Control | ISO 27001 | GDPR | PCI-DSS | AutoSOC capability | Status |
|---------|-----------|------|---------|--------------------|--------|
| Data at rest — access restriction | A.8.3 | Art.32 | 3.5 | Local DB file set owner-only (0600) on POSIX; XDG data dir | ✅ |
| Secrets at rest | A.8.24 | Art.32 | 3.6 | API keys/tokens in owner-only DB; **enterprise stack: AES-256-GCM** | ◐ desktop / ✅ enterprise |
| Data in transit | A.8.24 | Art.32 | 4.1 | TLS via reverse proxy (documented deployment); Telegram/VT over HTTPS | 👤 deploy |
| Data minimization | — | Art.5(1)(c) | 3.1 | Logs capped/truncated; only security-relevant telemetry collected | ✅ |
| Retention limitation | A.8.10 | Art.5(1)(e) | 3.1 | Configurable log retention + purge | ✅ |
| Secret redaction in logs | A.8.15 | Art.32 | 3.4 | Tokens scrubbed from client error paths (Telegram/NVIDIA/FortiGate/intel) | ✅ |
| Breach detection (72h) | A.5.24 | Art.33 | — | Detection + alerting supports the 72-hour breach-notification duty | 🧾 |

## 6. Change & configuration, resilience

| Control | ISO 27001 | SOC 2 | AutoSOC capability | Status |
|---------|-----------|-------|--------------------|--------|
| Change auditing | A.8.32 | CC8.1 | Config changes (firewall, keys, destinations, roles) audit-logged | ✅ 🧾 |
| Resilient network calls | A.8.14 | A1.2 | `net.retry_request` bounded backoff on all outbound integrations | ✅ |
| Failover | A.8.14 | A1.2 | Enterprise agent: primary/backup server failover | ✅ (enterprise) |
| Secure SDLC / testing | A.8.25–8.29 | CC8.1 | 169-test suite; SSRF guards; input validation; no `shell=True`/`eval` | ✅ 🧾 |

---

## What remains the operator's responsibility (👤)

A product cannot make an organization compliant on its own. To pass an audit,
the deploying organization must still:

1. **Terminate TLS** in front of the collector/API (reverse proxy) — AutoSOC's
   LAN transports are plain HTTP by design and expect this.
2. **Own the risk assessment, policies, and staff training** (ISO 27001 Clauses
   4–10; the ISMS itself is organizational, not a feature).
3. **Manage physical & cloud infrastructure security** of the host.
4. **Configure retention** to the legally required period for their jurisdiction.
5. **Rotate credentials and review access** on the schedule their policy defines.

## Honest gaps (not yet claimed as met)

- **Full at-rest encryption of the desktop DB** — currently protected by
  owner-only file permissions; database-level encryption (SQLCipher) is 🗺️
  roadmap. The enterprise stack already encrypts stored secrets with AES-256-GCM.
- **Enforced MFA for the console** — Telegram linking exists; mandatory MFA is ◐.
- **Automated evidence packs** (one-click auditor export bundle) — 🗺️ roadmap;
  today the audit-log CSV export is the building block.

---

*Verify the audit log's integrity anytime: **SOC Console → Admin → Verify
Integrity**. Export evidence with **Export CSV**. Full toolset context in
[SOC_ANALYST_TOOLKIT.md](SOC_ANALYST_TOOLKIT.md).*
