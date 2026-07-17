# AutoSOC Enterprise (SOAR/EDR) — distributed architecture

A distributed, multi-tenant SOAR/EDR built for MSSPs and small/mid data
centers. This is a **separate architecture** from the desktop AutoSOC app in
the repository root — a different, cloud-native stack:

```
enterprise/
├── server/   FastAPI async backend (auth, RBAC, multi-tenancy, AI, SOAR)
├── agent/    C++ EDR agent (process tree, heartbeat, failover, anti-tamper)
└── web/      React + Cytoscape.js interactive network map
```

Tech stack: **C++** agents · **Python FastAPI** async backend ·
**PostgreSQL/TimescaleDB** (SQLite for dev) · **React/Cytoscape.js** UI.

## Status of this codebase

| Component | State | Verified here |
|---|---|---|
| **server/** | Complete, runnable | ✅ boots (uvicorn) + full pytest suite (6 e2e tests) green |
| **agent/** (C++) | Complete, idiomatic | ⚙️ anti-tamper module compiles; full build needs libcurl-dev + CMake + network for FetchContent (not in this sandbox) |
| **web/** (React) | Complete | ⚙️ real component; needs `npm install && npm run build` in a Node toolchain |

Nothing is a stub — the parts not executed here are gated only by missing
build toolchains/hardware (Windows SDK, FortiGate, a browser), not by TODOs.

## Modules (mapped to the brief)

1. **Two-stage auth (OS bootstrap → Zero-Trust RBAC)** — `server/app/os_bootstrap.py`,
   `routers/auth.py`, `security.py`, `permissions.py`. OS admin password
   (PAM/Windows) ⇒ super-admin; super-admin creates tenants + employees with a
   granular permission set; employees get a scoped JWT.
2. **Multi-tenancy** — `middleware.py` validates the tenant on every request;
   `deps.py` scopes every query. Cross-tenant access is a 403.
3. **Process tree + anti-tamper + heartbeat** — agent `process_tree.*`,
   `anti_tamper.*`; server `services/heartbeat.py` raises "suspected
   compromise" when pings stop without a shutdown.
4. **Interactive network map** — `routers/network.py` (tenant-scoped JSON +
   WebSocket stream); `web/src/NetworkMap.jsx` (Cytoscape, permission-gated
   context actions).
5. **Failover + i18n** — agent `http_client.*` (primary/backup rotation);
   `server/app/i18n/` (EN/RU/AZ for UI, logs, Telegram).
6. **AI analyst + rate limiter + FortiGate SOAR** — `services/ai_analyst.py`
   (MITRE ATT&CK), `services/telegram.py` (5s aggregation + rate limit + i18n +
   Rollback button), `services/fortigate.py` (retry policy), `services/soar.py`
   (isolate → FortiGate → Telegram). API keys are AES-256-GCM encrypted
   (`security.py`).

## Run the server

```bash
cd enterprise/server
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# dev (SQLite):
.venv/bin/uvicorn app.main:app --reload
# → http://localhost:8000/docs
```

Production env (PostgreSQL/TimescaleDB + real secrets):

```bash
export AUTOSOC_ENT_DATABASE_URL="postgresql+asyncpg://user:pass@db:5432/autosoc"
export AUTOSOC_ENT_JWT_SECRET="$(openssl rand -base64 48)"
export AUTOSOC_ENT_MASTER_KEY="$(openssl rand -base64 32)"   # 32 bytes → AES-256
```

Demo flow: `POST /auth/bootstrap` with your OS admin login → super-admin token →
`POST /auth/tenants` → `POST /auth/users` → agent `POST /agents/enroll` →
`POST /agents/heartbeat`. Swagger UI at `/docs`.

Tests:

```bash
cd enterprise/server && .venv/bin/python -m pytest -q
```

## Build the agent

```bash
cd enterprise/agent
cmake -B build && cmake --build build -j      # needs libcurl-dev + CMake
AUTOSOC_SERVERS=http://primary:8000,http://backup:8000 \
AUTOSOC_ENROLLMENT_TOKEN=enr-... sudo ./build/autosoc-agent
```

## Run the web UI

```bash
cd enterprise/web
npm install
VITE_API_BASE=http://localhost:8000 npm run dev   # → http://localhost:5173
```

## Security notes

- Passwords: PBKDF2-HMAC-SHA256; JWT: HS256 with per-request tenant + perms.
- Integration secrets: AES-256-GCM at rest; redacted from all error strings.
- Agent transport is token-authenticated; put TLS (mTLS) in front for prod.
- The super-admin bypasses tenant scoping by design — protect the host account.
