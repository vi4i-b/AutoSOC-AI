#!/usr/bin/env python3
"""AutoSOC endpoint agent — standalone, stdlib only.

Copy this file to any server (or let the AutoSOC collector serve it over
``GET /agent``) and run one command. It enrolls with the collector, then
periodically reports host telemetry (hostname, OS, local IPs, uptime, running
processes) and ships new log lines.

Usage:
    python3 autosoc_agent.py --server http://<collector-ip>:8787 --token <TOKEN>

Common flags:
    --interval N        seconds between reports (default 30)
    --once              collect and send a single report, then exit
    --log-file PATH     extra log file(s) to ship (repeatable)
    --name NAME         override the reported hostname
    --agent-id ID       override the stable agent id

Notes:
 - Only the standard library is used, so any Python 3.6+ works.
 - Reading system logs (e.g. /var/log/auth.log) usually needs root; run with
   sudo for full log visibility. Without it, the agent still reports host
   telemetry and skips unreadable files.
 - The transport is plain HTTP with a bearer token — intended for a trusted
   LAN or behind a TLS reverse proxy.
"""

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_INTERVAL = 30
DEFAULT_LOG_FILES = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
FIRST_READ_TAIL_LINES = 50
MAX_LINES_PER_FILE = 200
HTTP_TIMEOUT = 15


# ── host identity ────────────────────────────────────────────────────

def stable_agent_id(override=""):
    if override:
        return override.strip()
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
                if value:
                    return "agent_" + hashlib.sha1(value.encode()).hexdigest()[:12]
        except OSError:
            continue
    seed = f"{socket.gethostname()}::{platform.system()}::{_first_mac()}"
    return "agent_" + hashlib.sha1(seed.encode()).hexdigest()[:12]


def _first_mac():
    try:
        import uuid

        return "%012x" % uuid.getnode()
    except Exception:
        return "unknown"


# ── network ──────────────────────────────────────────────────────────

def primary_ip():
    """Best-effort primary LAN IP (the source IP used to reach the network)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def all_ipv4():
    addresses = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    # Prefer richer data from `ip` when available (Linux).
    out = _run(["ip", "-o", "-4", "addr", "show"])
    if out:
        import re

        for match in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", out):
            addresses.add(match.group(1))
    return sorted(addresses)


# ── processes ────────────────────────────────────────────────────────

def collect_processes(limit=15):
    if os.name == "nt":
        return _windows_processes(limit)
    return _posix_processes(limit)


def _posix_processes(limit):
    out = _run(["ps", "-eo", "pid,comm,pcpu,pmem", "--sort=-pcpu"])
    if not out:
        out = _run(["ps", "-eo", "pid,comm,pcpu,pmem"])
    if not out:
        return {"count": 0, "top": []}
    lines = out.strip().splitlines()[1:]
    top = []
    for line in lines[:limit]:
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        pid, name, cpu, mem = parts[0], parts[1], parts[2], parts[3]
        top.append({"pid": pid, "name": name, "cpu": cpu, "mem": mem})
    return {"count": len(lines), "top": top}


def _windows_processes(limit):
    out = _run(["tasklist", "/fo", "csv", "/nh"])
    if not out:
        return {"count": 0, "top": []}
    import csv
    import io

    rows = list(csv.reader(io.StringIO(out)))
    top = []
    for row in rows[:limit]:
        if len(row) >= 5:
            top.append({"pid": row[1], "name": row[0], "cpu": "", "mem": row[4]})
    return {"count": len(rows), "top": top}


# ── logs ─────────────────────────────────────────────────────────────

class LogTailer:
    """Tracks per-file read offsets and yields new lines each cycle."""

    def __init__(self, paths):
        self.offsets = {}
        self.paths = [p for p in paths if p]

    def read_new(self):
        entries = []
        for path in self.paths:
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                first_seen = path not in self.offsets
                start = self.offsets.get(path, 0)
                if first_seen or start > size:  # first read or rotation
                    start = 0
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(start)
                    new_lines = handle.readlines()
                    self.offsets[path] = handle.tell()
            except (OSError, PermissionError):
                continue

            if first_seen and len(new_lines) > FIRST_READ_TAIL_LINES:
                new_lines = new_lines[-FIRST_READ_TAIL_LINES:]
            source = os.path.basename(path)
            for line in new_lines[-MAX_LINES_PER_FILE:]:
                line = line.rstrip("\n")
                if line.strip():
                    entries.append({"source": source, "severity": _guess_severity(line), "message": line})
        return entries


def _guess_severity(line):
    lowered = line.lower()
    if any(word in lowered for word in ("failed password", "authentication failure", "error", "denied", "invalid user")):
        return "warn"
    if any(word in lowered for word in ("critical", "fatal", "segfault")):
        return "critical"
    return "info"


# ── telemetry ────────────────────────────────────────────────────────

def uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as handle:
            return int(float(handle.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def logged_in_users():
    out = _run(["who"])
    if not out:
        return []
    return [line.split()[0] for line in out.strip().splitlines() if line.split()]


def collect_telemetry():
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "system": platform.system(),
        "platform": platform.platform(),
        "release": platform.release(),
        "python": platform.python_version(),
        "primary_ip": primary_ip(),
        "ipv4": all_ipv4(),
        "uptime_seconds": uptime_seconds(),
        "logged_in_users": logged_in_users(),
        "processes": collect_processes(),
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ── transport ────────────────────────────────────────────────────────

def _run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
        return result.stdout if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def post(server, path, token, payload):
    url = server.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="replace")
            return True, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return False, str(exc)


# ── main loop ────────────────────────────────────────────────────────

def run(args):
    agent_id = stable_agent_id(args.agent_id)
    hostname = args.name or socket.gethostname()
    system = platform.system()
    tailer = LogTailer(DEFAULT_LOG_FILES + list(args.log_file or []))

    print(f"[autosoc-agent] id={agent_id} host={hostname} -> {args.server}")
    ok, result = post(args.server, "/api/v1/enroll", args.token, {
        "agent_id": agent_id, "hostname": hostname, "platform": system, "local_ip": primary_ip(),
    })
    if ok:
        print("[autosoc-agent] enrolled")
    else:
        print(f"[autosoc-agent] enrollment failed: {result}", file=sys.stderr)
        if args.once:
            return 1

    while True:
        telemetry = collect_telemetry()
        logs = tailer.read_new()
        ok, result = post(args.server, "/api/v1/report", args.token, {
            "agent_id": agent_id,
            "hostname": hostname,
            "platform": system,
            "local_ip": telemetry.get("primary_ip", ""),
            "telemetry": telemetry,
            "logs": logs,
        })
        stamp = datetime.now().strftime("%H:%M:%S")
        if ok:
            print(f"[autosoc-agent] {stamp} report sent (logs={len(logs)}, "
                  f"procs={telemetry['processes']['count']})")
        else:
            print(f"[autosoc-agent] {stamp} report failed: {result}", file=sys.stderr)

        if args.once:
            return 0 if ok else 1
        try:
            time.sleep(max(args.interval, 5))
        except KeyboardInterrupt:
            print("\n[autosoc-agent] stopped")
            return 0


def build_parser():
    parser = argparse.ArgumentParser(description="AutoSOC endpoint agent")
    parser.add_argument("--server", required=True, help="Collector base URL, e.g. http://10.0.0.5:8787")
    parser.add_argument("--token", required=True, help="Ingestion token from the SOC console")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Seconds between reports")
    parser.add_argument("--once", action="store_true", help="Send a single report and exit")
    parser.add_argument("--log-file", action="append", help="Extra log file to ship (repeatable)")
    parser.add_argument("--name", help="Override the reported hostname")
    parser.add_argument("--agent-id", help="Override the stable agent id")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n[autosoc-agent] stopped")
        return 0


if __name__ == "__main__":
    sys.exit(main())
