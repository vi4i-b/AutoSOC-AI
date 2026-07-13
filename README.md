# AutoSOC AI

AutoSOC AI is a desktop cybersecurity assistant for small teams and local
networks. It combines network scanning, risky-port analysis, firewall
management, AI explanations, and Telegram alerting in one application.

Runs on **Windows** and **Linux (Ubuntu)**.

Documentation in other languages: [Русский](docs/ru/README.md)

## What it does

- Scans a target for tracked TCP ports (nmap).
- Detects risky services and computes a risk score.
- Shows a live dashboard: devices, open ports, risk score, incidents, Telegram status.
- Opens/blocks ports through the system firewall (netsh on Windows, iptables on Linux).
- Detects login brute-force (Windows Security log / Linux auth.log).
- Runs Port Canary decoy listeners and logs threat events.
- Sends scan results and alerts to Telegram.
- Explains findings via an AI copilot (NVIDIA API, OpenAI, or local Ollama — with an offline fallback).
- **Analyzes URLs for phishing** — URL structure, TLS certificate, page content,
  spelling/homograph checks, and an AI verdict (see below).
- **SOC Operations Console** — a dedicated window for analysts/sysadmins:
  triage queue, incident cases, endpoint/agent fleet, threat-intel watchlist,
  log search, and KPI metrics.

## Anti-phishing engine

Open the **Anti-Phishing Analysis** tab and enter a URL:

- **Quick Check** — offline URL heuristics only (IP-literal hosts, punycode /
  homograph domains, brand look-alikes, suspicious TLDs, shorteners, `@`
  tricks, long/hyphen-heavy hosts).
- **Full Analyze** — additionally fetches the page (SSRF-guarded, size- and
  time-limited, JavaScript never executed), inspects the **TLS certificate**,
  scans page **content** (off-site credential forms, urgency language, brand
  impersonation, iframes/obfuscation), checks **spelling** (common
  misspellings + Cyrillic/Greek homograph text), and — if a NVIDIA model key
  is set — adds a language-model **verdict** that reviews the page text for
  spelling/grammar and phishing intent.

Each finding is shown as a weighted signal, combined into a 0–100 score and a
verdict (Likely Safe → Questionable → Suspicious → Dangerous). Results can be
promoted to a SOC incident with one click.

Paste your NVIDIA API key in the left sidebar (**AI Engine (NVIDIA)** card) to
enable AI verdicts and the security copilot; it is stored in the per-user,
owner-only database.

## SOC Operations Console

Click **Open SOC Console** in the left sidebar. Tabs:

- **Triage Queue** — all security events, severity-filtered; promote to incident.
- **Incidents** — case management with status, severity, assignee, MITRE
  ATT&CK technique, and investigation notes.
- **Endpoints & Agents** — start the built-in collector and onboard servers.
- **Detection Rules** — a SIEM-style rule engine (see below).
- **Threat Intel** — IOC watchlist with add/lookup/match.
- **Log Search** — free-text search over centrally ingested logs.
- **Metrics** — open/critical/resolved cases, event volume, fleet size.

### Detection rules (SIEM-style)

The **Detection Rules** tab ships a default baseline of ~21 rules — the kind
of content most SIEMs enable out of the box — mapped to MITRE ATT&CK:
SSH/FortiGate brute-force, root login, new user / added-to-sudo, sudo failures,
reverse shell & `curl|sh`, web-shell indicators, security-service-stopped and
log-cleared (defense evasion), plus telemetry rules — **connection to a
block-listed / IOC IP** (auto-block), **listener on a backdoor port**,
**connection to a C2-style port**, and **offensive/miner process running**.

Rules run automatically on every ingested log line (agent + syslog) and every
endpoint telemetry snapshot. A match raises a security event and, per the
rule, opens an incident and/or blocks the source IP. Each rule can be
enabled/disabled with a switch; built-ins can be disabled and **custom
log-pattern rules added/removed** (regex, severity, MITRE, threshold/window,
auto-incident, auto-block).

### Endpoint agents (collect logs/processes/IP from any server)

AutoSOC ships a working agent + collector. In **SOC Console → Endpoints &
Agents**, click **Start Collector**, then run the shown one-liner on any
server:

```bash
curl -fsSL http://<autosoc-ip>:8787/agent | sudo python3 - \
  --server http://<autosoc-ip>:8787 --token <ingestion-token>
```

The endpoint enrolls and streams its **hostname, OS, LAN IPs, uptime, running
processes, and system logs** (`/var/log/auth.log`, `syslog`, …) back to the
console — visible under **Details** and **Log Search**. The agent is pure
Python stdlib (no install needed) and authenticates with a revocable bearer
token.

### Network firewalls & syslog (FortiGate, Palo Alto, MikroTik, pfSense)

For devices that can't run the agent, use **SOC Console → Endpoints & Agents →
Network Firewall & Syslog**:

- **Start Syslog** (UDP :5514) and point the device's syslog at the shown
  target — logs flow into Log Search, and repeated login failures (incl.
  FortiGate `action=login status=failed`) raise brute-force events.
- **Block-list feed** — AutoSOC serves blocked IPs at `/blocklist.txt`; point a
  FortiGate Threat Feed / Palo Alto EDL / pfBlockerNG / MikroTik at it to
  auto-drop them.
- **Firewall Integration** — configure a FortiGate REST connector to push
  blocks in real time.

Every block (guard, canary, brute-force, manual) is fanned out to the feed, the
configured appliance, and the local host firewall together.

See [docs/AGENTS_AND_ROADMAP.md](docs/AGENTS_AND_ROADMAP.md) for the full agent
architecture (systemd service, mTLS/pull-action hardening), the FortiGate
setup, and the product/monetization roadmap. The agent script lives at
[agent/autosoc_agent.py](agent/autosoc_agent.py).

## Project structure

```
main.py                  # entry point
autosoc/
├── analyzer.py          # risk catalog and scoring
├── auth.py              # login, registration, lockout, remember-me
├── canary.py            # decoy port listeners
├── database.py          # SQLite storage (users, scans, events, incidents, agents, iocs, logs)
├── env.py               # .env loader
├── guard.py             # traffic-spike (DDoS) monitor
├── logging_setup.py     # console + rotating file logging
├── paths.py             # per-user data dir, resource paths
├── ports.py             # tracked ports (single source of truth)
├── scanner.py           # nmap wrapper
├── security_utils.py    # PBKDF2 password hashing
├── validators.py        # input validation
├── ai/                  # AI providers (nvidia.py, expert.py)
├── agents/              # log/telemetry ingestion
│   ├── server.py        #   HTTP collector (enroll/report, agent + blocklist feed)
│   └── syslog_server.py #   agentless syslog receiver (FortiGate/devices)
├── detection/           # SIEM-style rule engine
│   ├── engine.py        #   evaluate logs + telemetry, fire alerts
│   └── default_rules.py #   default baseline (MITRE-mapped)
├── phishing/            # anti-phishing engine
│   ├── analyzer.py      #   orchestrator → PhishingReport
│   ├── url_features.py  #   URL heuristics (offline)
│   ├── fetcher.py       #   SSRF-safe page fetch + HTML parse
│   ├── tls_check.py     #   TLS certificate inspection
│   ├── content_features.py #  form/urgency/impersonation checks
│   └── spelling.py      #   misspelling + homograph detection
├── system/              # OS integration
│   ├── commands.py      #   safe subprocess execution (no shell)
│   ├── firewall.py      #   netsh / iptables backends
│   ├── appliance.py     #   FortiGate REST + feed-only connector
│   ├── response.py      #   unified block (feed + appliance + host)
│   ├── hardening.py     #   service-level hardening per OS
│   ├── log_monitor.py   #   failed-login monitoring per OS
│   ├── netinfo.py       #   local IPs, remote-target detection
│   ├── os_auth.py       #   Windows account login (LogonUserW)
│   └── privileges.py    #   admin/root checks
├── telegram/            # bot client + long-polling listener
└── ui/                  # CustomTkinter windows
    ├── login.py         #   login / registration
    ├── dashboard.py     #   main dashboard (logic)
    ├── dashboard_layout.py  # dashboard widgets
    └── soc_console.py   #   SOC Operations Console
agent/autosoc_agent.py   # standalone endpoint agent (stdlib only)
tests/                   # unit tests
```

## Installation

### Ubuntu / Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk nmap libpcap0.8

git clone https://github.com/vi4i-b/AutoSOC-AI.git
cd AutoSOC-AI
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env        # then fill in your tokens
```

Run:

```bash
# Regular mode (scanning, dashboard, Telegram, AI):
.venv/bin/python main.py

# With firewall management, brute-force monitoring and Guard (needs root):
sudo -E .venv/bin/python main.py
```

Notes for Linux:
- Firewall control uses **iptables**; rules are tagged `AutoSOC_*`.
- Brute-force detection reads `/var/log/auth.log` (root or `adm` group).
- OS-account login is Windows-only; on Linux use a local AutoSOC account
  (register in the login window).

### Windows

1. Install Python 3.12+, [Nmap](https://nmap.org/download.html) and
   (optionally, for Guard) [Npcap](https://npcap.com/).
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and fill in your tokens.
4. Run as Administrator for firewall management:

```powershell
python main.py
```

## Configuration (.env)

See [.env.example](.env.example) for the full annotated list. Key values:

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather (enables alerts) |
| `NVIDIA_API_KEY` | NVIDIA-hosted models for the copilot |
| `AI_PROVIDER` / `OPENAI_API_KEY` / `OLLAMA_URL` | Expert-mode AI provider selection |
| `AUTOSOC_DATA_DIR` | Override the data directory |
| `AUTOSOC_LOG_LEVEL` | DEBUG / INFO / WARNING / ERROR |

Application data (database, logs, AI memory) is stored per user:
`%APPDATA%\AutoSOC` on Windows, `~/.local/share/autosoc` on Linux.

## How Telegram linking works

1. Start the app and open the bot (button in the login window).
2. Send `/start` to the bot and copy the returned `Telegram Chat ID`.
3. Paste it into the registration form (the app also captures it automatically).
4. After login, scan results and alerts are sent to that chat.

## How the AI works

With `AI_PROVIDER=auto` the expert answers use, in order of availability:
OpenAI (if `OPENAI_API_KEY` is set) → local Ollama → built-in offline expert
mode. The dashboard copilot additionally uses the NVIDIA API when
`NVIDIA_API_KEY` is set. The most convenient free local option is
`Ollama + llama3.1:8b`.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Building a binary

```bash
pip install -r requirements-dev.txt
python -m PyInstaller --clean main.spec
```

The result appears in `dist/AutoSOC` (`dist/AutoSOC.exe` on Windows).

## Security

See [SECURITY.md](SECURITY.md) for the security model: secrets handling,
password storage, account lockout, privileges, and what data leaves the
machine. **Only scan hosts and networks you own or are authorized to test.**

## Additional documents

- [docs/CODE_NAVIGATION.md](docs/CODE_NAVIGATION.md)
- [docs/ru/README.md](docs/ru/README.md)
- [docs/HACKATHON_PRESENTATION.md](docs/HACKATHON_PRESENTATION.md)
