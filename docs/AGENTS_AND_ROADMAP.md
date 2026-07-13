# AutoSOC — Endpoint Agents, SOC Workflow & Business Roadmap

This document covers three things the product needs to be more than a demo:

1. What a SOC analyst actually does (so the console matches the job).
2. How to collect logs and security telemetry from servers and endpoints
   ("install agents everywhere").
3. How AutoSOC can differentiate and make money.

---

## 1. What a SOC analyst does (and how AutoSOC maps to it)

A Security Operations Center analyst runs a repeating loop. AutoSOC's SOC
Console is built around exactly this loop:

| SOC activity | What it means | Where it lives in AutoSOC |
|---|---|---|
| **Monitoring** | Watch a stream of alerts from many sources | Triage Queue (security events) |
| **Triage** | Decide if an alert is real, its severity, and priority | Triage Queue → "→ Incident" |
| **Investigation** | Pull context, timeline, related logs | Incident notes + Log Search |
| **Case management** | Track an incident through its lifecycle | Incidents tab (status, assignee) |
| **Threat intel** | Compare artifacts against known-bad indicators | Threat Intel (IOC watchlist) |
| **Containment/response** | Block IPs/ports, isolate hosts | Dashboard firewall + agent actions |
| **Reporting/metrics** | MTTD, MTTR, alert volume, shift handover | Metrics tab |
| **Threat hunting** | Proactively search telemetry for badness | Log Search + IOC matching |

Tiers, for context:
- **Tier 1** — triage and escalate; needs speed and a clean queue.
- **Tier 2** — deep investigation and response; needs context and history.
- **Tier 3 / Threat hunting** — proactive hunts, detection engineering.
- **SOC manager** — cares about KPIs (MTTD/MTTR), coverage, staffing.

Key metrics the market expects: **MTTD** (mean time to detect), **MTTR**
(mean time to respond), alert volume, false-positive rate, and detection
coverage (e.g. against MITRE ATT&CK).

---

## 2. Collecting logs from servers and endpoints

The core promise of AutoSOC is **centralization**: one place that ingests
telemetry from many machines. There are two complementary paths.

### 2.0 What's implemented today (quick start)

A working agent + collector already ships in the app:

1. Open the **SOC Console → Endpoints & Agents** tab and click
   **Start Collector**. AutoSOC starts an HTTP collector (default port 8787)
   and shows a one-line install command with your server's LAN address and an
   ingestion token.
2. On the target server, run that command:

   ```bash
   curl -fsSL http://<autosoc-ip>:8787/agent | sudo python3 - \
     --server http://<autosoc-ip>:8787 --token <ingestion-token>
   ```

   The collector serves the agent script itself over `GET /agent`, so nothing
   needs to be pre-installed — just Python 3 (already on any Linux server).
   `sudo` lets the agent read system logs like `/var/log/auth.log`.
3. Within a few seconds the endpoint appears in the tab as **online**, and
   **Details** shows its hostname, OS, primary/all IPv4 addresses, uptime,
   logged-in users, and top processes. Its log lines flow into **Log Search**.

Run the agent as a background service to keep it reporting:

```bash
# quick background run
nohup sudo python3 autosoc_agent.py --server http://<ip>:8787 --token <token> \
  --interval 30 >/var/log/autosoc-agent.log 2>&1 &

# or as a systemd unit (recommended for servers)
sudo tee /etc/systemd/system/autosoc-agent.service >/dev/null <<'UNIT'
[Unit]
Description=AutoSOC endpoint agent
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/autosoc/autosoc_agent.py \
  --server http://<autosoc-ip>:8787 --token <ingestion-token> --interval 30
Restart=always
User=root
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl enable --now autosoc-agent
```

The agent uses **only the Python standard library**, so it runs on any host
with Python 3 — no dependencies to install.

**What the agent collects today:** hostname/FQDN, OS/platform, primary LAN IP
and all IPv4 addresses, uptime, logged-in users, running processes (PID, CPU%,
MEM%, name), and new lines from `/var/log/auth.log`, `/var/log/secure`,
`/var/log/syslog` (plus any `--log-file` you add).

**Security of the current transport:** the agent authenticates with a bearer
token (constant-time compared, revocable via **Regenerate Token**); request
bodies are size-capped and never executed. It is plain HTTP — intended for a
trusted LAN or behind a TLS reverse proxy. The mTLS/pull-action hardening
below is the production next step.

### 2.1 Agentless collection (fastest to ship)

Good for infrastructure you already control, no software to install on every
box:

- **Syslog / RFC 5424** — point servers, routers, firewalls at an AutoSOC
  syslog listener (UDP/TCP 514, or TLS 6514). Almost every Linux box and
  network device can forward syslog natively.
- **Windows Event Forwarding (WEF)** — collect Windows Security logs to a
  collector, then into AutoSOC.
- **API/webhook ingestion** — cloud services (Microsoft 365, Google
  Workspace, AWS CloudTrail, Cloudflare) push events to an AutoSOC webhook.

The agent path (2.0) already feeds the `ingested_logs` store and Log Search;
agentless syslog/webhook listeners writing into the same store are the next
addition for onboarding devices that can't run an agent.

### 2.2 The AutoSOC agent (deeper visibility)

For endpoints where you want richer, host-level telemetry and the ability to
act (isolate, kill process, collect a file), ship a lightweight agent.

**Recommended architecture:**

```
   Endpoint (server / workstation)                AutoSOC Server
 ┌───────────────────────────────┐            ┌────────────────────────┐
 │  autosoc-agent (Go or Python) │            │  Ingestion API (HTTPS) │
 │   • tails /var/log, journald  │  mTLS      │   • /enroll            │
 │   • Windows Event Log         │──────────► │   • /heartbeat         │
 │   • osquery for host state    │  outbound  │   • /logs              │
 │   • local rules → events      │  only      │   • /actions (pull)    │
 │   • executes response actions │◄───────────│  SQLite/Postgres store │
 └───────────────────────────────┘            └────────────────────────┘
```

**Design principles:**

- **Lightweight & cross-platform.** A single static binary (Go is ideal;
  a Python agent works for a PoC). Small memory/CPU budget so it can run on
  production servers without complaints.
- **Outbound-only, mTLS.** The agent dials home over HTTPS with a client
  certificate; no inbound ports opened on the endpoint. This is safer and
  firewall-friendly.
- **Token enrollment.** The SOC Console generates an enrollment token
  (already implemented: *Endpoints & Agents → Generate Enrollment Token*).
  The agent presents `agent-id + token` once to `/enroll` and receives a
  client certificate. After that it authenticates with the cert.
- **Heartbeat + health.** Periodic `/heartbeat` sets the endpoint to
  `online` and carries basic host health; missed heartbeats flip it to
  `stale/offline` in the console.
- **Batched, compressed log shipping** to `/logs` with at-least-once
  delivery and local spooling when the server is unreachable.
- **Pull-based response actions.** The agent polls `/actions` for commands
  (isolate host, block IP, collect artifact). Pull avoids inbound exposure.
- **Tamper resistance.** Run as a protected service, sign the binary, and
  alert if the agent stops reporting.

**Don't reinvent everything.** Two credible strategies:

1. **Build a thin agent** for the AutoSOC-specific parts (enrollment,
   response actions) and **embed osquery** for host inspection — osquery
   turns the OS into a SQL-queryable surface and is battle-tested.
2. **Integrate an existing open-source stack** rather than compete with it:
   - **Wazuh** (agents + rules) or **Elastic/Beats** (Filebeat, Winlogbeat)
     for collection; AutoSOC becomes the analyst-friendly UI + AI layer on
     top.
   - **Fluent Bit / Vector** as the universal log shipper into the
     ingestion API.

**Suggested MVP order:**
1. Syslog + webhook ingestion (agentless) → immediate multi-host value.
2. Python reference agent: enroll → heartbeat → ship auth.log / Event Log.
3. Response actions (block IP via the existing firewall backends).
4. osquery integration for host state and hunting.
5. mTLS + signed Go binary for production hardening.

---

## 3. Differentiation & monetization

The SIEM/SOC market is crowded (Splunk, Elastic, Wazuh, Microsoft Sentinel).
To win a niche and earn revenue, lean into what AutoSOC already is.

### Where AutoSOC can be different

- **AI-native, plain-language SOC copilot.** Not just "search logs" — the
  assistant already explains findings, and the anti-phishing engine already
  produces AI verdicts. Double down: auto-summarize incidents, suggest next
  response steps, and draft the shift handover report. This is the wedge
  against heavyweight, expert-only tools.
- **Multilingual by design.** The UI and AI answer in Azerbaijani, Russian,
  and English. Regional SMB/MSSP markets are underserved by English-only
  enterprise tools — that is a real moat locally.
- **Anti-phishing built in.** Most SIEMs don't ship a URL/phishing analyzer.
  AutoSOC does (URL + TLS + content + spelling + AI). Package it as a
  standalone value-add for help desks and email teams.
- **Zero-to-value in minutes.** A desktop app that scans, detects, and alerts
  to Telegram with almost no setup. Enterprise SOC suites take weeks to
  deploy; AutoSOC's speed is a selling point for small teams.
- **Telegram-first alerting.** Cheap, instant, mobile — perfect for small
  teams and MSSPs who can't staff a 24/7 console.

### Monetization models

- **Freemium / open core.** Single-host scanning, anti-phishing, and the
  dashboard are free. Charge for multi-endpoint agents, centralized log
  retention, AI features, and role-based access.
- **Per-endpoint subscription.** The classic EDR/SOC pricing: €X per endpoint
  per month. The agent + console architecture above is exactly what this
  bills against.
- **MSSP tier ("SOC-as-a-Service in a box").** Sell to managed security
  providers who run AutoSOC across many client tenants. Add multi-tenancy,
  branded reports, and SLA metrics.
- **AI usage tier.** Bring-your-own NVIDIA/OpenAI key (already supported) on
  the low tier; a managed, higher-limit AI copilot on paid tiers.
- **Compliance reporting add-on.** Auto-generate ISO 27001 / PCI-DSS / GDPR
  evidence from the audit and incident data. Compliance is a budget line SMBs
  will pay for.
- **Threat-intel feed subscription.** Curated IOC feeds that flow into the
  watchlist and auto-match against ingested logs.

### Concrete near-term roadmap

1. **Ingestion service** (syslog + webhook) → real centralization.
2. **Reference agent** (enroll/heartbeat/logs) → per-endpoint story.
3. **Detection rules engine** on ingested logs → alerts, not just storage.
4. **AI incident copilot**: summarize, correlate, recommend, auto-draft
   reports.
5. **Multi-tenant + RBAC** → unlock the MSSP market.
6. **Compliance report generator** → a paid add-on with clear ROI.

The short version: keep the fast, friendly, AI-driven, multilingual
experience as the differentiator; build the agent/ingestion backbone so it
scales past one machine; and monetize per-endpoint + AI + compliance, with an
MSSP tier as the growth lever.
