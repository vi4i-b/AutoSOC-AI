"""Embedded HTTP collector for endpoint agents.

Endpoints (all JSON unless noted):

    GET  /api/v1/ping        health check (no auth)
    GET  /agent              serves the standalone agent script (no auth;
                             the script is not secret — the token is)
    POST /api/v1/enroll      { agent_id, hostname, platform, local_ip }
    POST /api/v1/report      { agent_id, hostname, platform, local_ip,
                               telemetry:{...}, logs:[ "line" | {message,source,severity} ] }

Authentication: POST endpoints require ``Authorization: Bearer <ingestion
token>``; the token is compared in constant time. Request bodies are size-
capped and never executed. This is a LAN/PoC transport — put it behind TLS
(a reverse proxy) for anything beyond a trusted network. See
docs/AGENTS_AND_ROADMAP.md.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from autosoc.logging_setup import get_logger
from autosoc.paths import project_root

log = get_logger("agents.server")

MAX_BODY_BYTES = 5_000_000
MAX_LOG_LINES_PER_REPORT = 500
DEFAULT_PORT = 8787


def agent_script_path() -> str:
    return os.path.join(project_root(), "agent", "autosoc_agent.py")


class _CollectorHandler(BaseHTTPRequestHandler):
    server_version = "AutoSOC-Collector/1.0"

    # Route logging through our logger instead of stderr.
    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    @property
    def db(self):
        return self.server.autosoc_db

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        token = header[7:].strip() if header.startswith("Bearer ") else ""
        return self.db.verify_ingestion_token(token)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    # ── GET ──────────────────────────────────────────────────────────

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_landing()
            return
        if path == "/api/v1/ping":
            self._send_json(200, {"ok": True, "service": "autosoc-collector"})
            return
        if path in ("/agent", "/install", "/autosoc_agent.py"):
            self._serve_agent_script()
            return
        if path in ("/blocklist.txt", "/blocklist"):
            self._serve_blocklist()
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def _serve_blocklist(self):
        """Plain-text IP feed for network firewalls (FortiGate threat feed, Palo Alto EDL, …)."""
        ips = self.db.active_blocklist()
        body = ("\n".join(ips) + "\n").encode("utf-8") if ips else b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_landing(self):
        """Human-friendly page so a browser hitting the root isn't confused."""
        host = self.headers.get("Host", "this-host:8787")
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoSOC Collector</title>
<style>
 body{{background:#07111b;color:#dbe8f4;font-family:system-ui,Segoe UI,Arial,sans-serif;
      margin:0;padding:48px;line-height:1.5}}
 .card{{max-width:720px;margin:0 auto;background:#0b1623;border:1px solid #1d3347;
        border-radius:16px;padding:28px 32px}}
 h1{{margin:0 0 4px;font-size:24px}} .muted{{color:#87a5c0}}
 code,pre{{background:#08111b;border:1px solid #1f3449;border-radius:8px;color:#77beff}}
 code{{padding:2px 6px}} pre{{padding:14px;overflow:auto}}
 a{{color:#77beff}} .ok{{color:#5dd39e}} table{{border-collapse:collapse;margin:12px 0}}
 td{{padding:6px 14px 6px 0;vertical-align:top}}
</style></head><body><div class="card">
<h1>AutoSOC Collector <span class="ok">● online</span></h1>
<p class="muted">Endpoint log &amp; telemetry ingestion service. This is an API, not a website.</p>
<table>
<tr><td><a href="/api/v1/ping">/api/v1/ping</a></td><td class="muted">health check</td></tr>
<tr><td><a href="/agent">/agent</a></td><td class="muted">the endpoint agent script</td></tr>
<tr><td><a href="/blocklist.txt">/blocklist.txt</a></td><td class="muted">firewall block-list feed (FortiGate Threat Feed / Palo Alto EDL)</td></tr>
</table>
<p class="muted">Onboard a server (run on the target, needs your ingestion token):</p>
<pre>curl -fsSL http://{host}/agent | sudo python3 - \\
  --server http://{host} --token &lt;ingestion-token&gt;</pre>
<p class="muted">Get the token from the AutoSOC app: SOC Console &rarr; Endpoints &amp; Agents.</p>
</div></body></html>"""
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_agent_script(self):
        try:
            with open(agent_script_path(), "rb") as handle:
                body = handle.read()
        except OSError:
            self._send_json(404, {"ok": False, "error": "agent script not available on this server"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/x-python; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── POST ─────────────────────────────────────────────────────────

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if not self._authorized():
            self._send_json(401, {"ok": False, "error": "invalid or missing token"})
            return

        data = self._read_json()
        if data is None:
            self._send_json(400, {"ok": False, "error": "invalid or oversized JSON body"})
            return

        if path == "/api/v1/enroll":
            self._handle_enroll(data)
        elif path == "/api/v1/report":
            self._handle_report(data)
        else:
            self._send_json(404, {"ok": False, "error": "not found"})

    def _handle_enroll(self, data):
        agent_id = str(data.get("agent_id", "")).strip()
        if not agent_id:
            self._send_json(400, {"ok": False, "error": "agent_id required"})
            return
        self.db.mark_agent_seen(
            agent_id,
            hostname=str(data.get("hostname", ""))[:200],
            platform=str(data.get("platform", ""))[:200],
            ip_address=str(data.get("local_ip", ""))[:64],
        )
        self.db.add_audit_event("agent_enrolled", agent_id,
                                f"Agent enrolled from {self.address_string()}.")
        log.info("Agent enrolled: %s (%s)", agent_id, data.get("hostname", ""))
        self._send_json(200, {"ok": True, "agent_id": agent_id})

    def _handle_report(self, data):
        agent_id = str(data.get("agent_id", "")).strip()
        if not agent_id:
            self._send_json(400, {"ok": False, "error": "agent_id required"})
            return

        telemetry = data.get("telemetry") or {}
        self.db.mark_agent_seen(
            agent_id,
            hostname=str(data.get("hostname", ""))[:200],
            platform=str(data.get("platform", ""))[:200],
            ip_address=str(data.get("local_ip", ""))[:64],
        )
        try:
            self.db.save_agent_snapshot(agent_id, json.dumps(telemetry)[:200_000])
        except (TypeError, ValueError):
            pass

        stored = 0
        for entry in (data.get("logs") or [])[:MAX_LOG_LINES_PER_REPORT]:
            if isinstance(entry, dict):
                message = str(entry.get("message", ""))[:2000]
                source = str(entry.get("source", "agent"))[:120]
                severity = str(entry.get("severity", "info"))[:20]
            else:
                message = str(entry)[:2000]
                source = "agent"
                severity = "info"
            if message.strip():
                self.db.add_ingested_log(message, agent_id=agent_id, source=source, severity=severity)
                stored += 1

        self._send_json(200, {"ok": True, "stored_logs": stored})


class CollectorService:
    """Starts/stops the collector HTTP server in a background thread."""

    def __init__(self, db, host=None, port=None):
        self.db = db
        self.host = host or (os.getenv("AUTOSOC_COLLECTOR_HOST") or "0.0.0.0").strip()
        # port=0 is a valid request ("let the OS pick a free port"), so only
        # fall back to the env/default when port is None.
        self.port = int(port) if port is not None else int(os.getenv("AUTOSOC_COLLECTOR_PORT") or DEFAULT_PORT)
        self._httpd = None
        self._thread = None

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def start(self):
        """Return (ok, message)."""
        if self.running:
            return True, f"Collector already running on {self.host}:{self.port}"
        try:
            httpd = ThreadingHTTPServer((self.host, self.port), _CollectorHandler)
        except OSError as exc:
            log.warning("Collector failed to bind %s:%s — %s", self.host, self.port, exc)
            return False, f"Could not bind {self.host}:{self.port}: {exc}"

        httpd.autosoc_db = self.db
        httpd.daemon_threads = True
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, name="AutoSOCCollector", daemon=True)
        self._thread.start()
        # Ensure the token exists so the UI can show it immediately.
        self.db.get_or_create_ingestion_token()
        log.info("Collector listening on %s:%s", self.host, self.port)
        return True, f"Collector listening on {self.host}:{self.port}"

    def stop(self):
        if not self.running:
            return
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception as exc:
            log.debug("Collector stop error: %s", exc)
        finally:
            self._httpd = None
            self._thread = None
        log.info("Collector stopped")

    def address(self):
        return self.host, self.port
