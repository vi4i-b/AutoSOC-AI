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
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SS_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')

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


def os_pretty_name():
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()


def resources():
    """CPU/memory/disk/load — quick health context for the analyst."""
    data = {"cpu_count": os.cpu_count()}
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as handle:
            data["load_avg"] = handle.read().split()[:3]
    except OSError:
        pass
    try:
        mem = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                key = line.split(":", 1)[0]
                mem[key] = int(line.split()[1])
        total = mem.get("MemTotal", 0) // 1024
        avail = mem.get("MemAvailable", 0) // 1024
        if total:
            data["mem_total_mb"] = total
            data["mem_used_mb"] = total - avail
    except (OSError, ValueError, IndexError):
        pass
    out = _run(["df", "-Pm", "/"])
    if out:
        rows = out.strip().splitlines()
        if len(rows) >= 2:
            cols = rows[1].split()
            if len(cols) >= 5:
                data["disk_root"] = {"size_mb": cols[1], "used_mb": cols[2], "use_pct": cols[4]}
    return data


def network_sockets(limit=200):
    """Listening ports and active connections, each with the owning process.

    This is the core "what process opens what" view — a listener on an odd
    port or a connection to an unknown remote is how backdoors and C2 show up.
    """
    if os.name == "nt":
        return _windows_sockets(limit)

    out = _run(["ss", "-tunap"])
    listening, connections = [], []
    if not out:
        return {"listening": listening, "connections": connections, "note": "ss unavailable"}

    for line in out.splitlines():
        if not line.strip() or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        netid, state, local, peer = parts[0], parts[1], parts[4], parts[5]
        proc, pid = "", ""
        match = _SS_PROC_RE.search(line)
        if match:
            proc, pid = match.group(1), match.group(2)
        if state in ("LISTEN", "UNCONN"):
            listening.append({"proto": netid, "local": local, "pid": pid, "process": proc})
        elif state == "ESTAB":
            connections.append({"proto": netid, "local": local, "remote": peer,
                                "state": state, "pid": pid, "process": proc})
        if len(listening) + len(connections) >= limit:
            break
    return {"listening": listening, "connections": connections}


def _windows_sockets(limit):
    listening, connections = [], []
    names = {}
    tasks = _run(["tasklist", "/fo", "csv", "/nh"])
    if tasks:
        import csv
        import io

        for row in csv.reader(io.StringIO(tasks)):
            if len(row) >= 2:
                names[row[1].strip()] = row[0]
    out = _run(["netstat", "-ano"])
    if not out:
        return {"listening": listening, "connections": connections}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto, local = parts[0], parts[1]
        if proto == "TCP" and len(parts) >= 5:
            state, pid = parts[3], parts[4]
            remote = parts[2]
        else:
            state, pid, remote = "", parts[-1], parts[2] if len(parts) > 2 else "*:*"
        proc = names.get(pid, "")
        if state == "LISTENING" or proto == "UDP":
            listening.append({"proto": proto.lower(), "local": local, "pid": pid, "process": proc})
        elif state == "ESTABLISHED":
            connections.append({"proto": proto.lower(), "local": local, "remote": remote,
                                "state": state, "pid": pid, "process": proc})
        if len(listening) + len(connections) >= limit:
            break
    return {"listening": listening, "connections": connections}


def recent_auth_failures(limit_lines=3000):
    """Quick count + top source IPs of failed logins from the local auth log."""
    result = {"count": 0, "top_sources": []}
    for path in ("/var/log/auth.log", "/var/log/secure"):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()[-limit_lines:]
        except (OSError, PermissionError):
            continue
        counts = {}
        total = 0
        for line in lines:
            if ("Failed password" in line or "authentication failure" in line
                    or "Invalid user" in line):
                total += 1
                found = _IPV4_RE.search(line)
                if found:
                    counts[found.group(0)] = counts.get(found.group(0), 0) + 1
        top = sorted(counts.items(), key=lambda item: -item[1])[:8]
        result = {"count": total, "top_sources": [{"ip": ip, "count": c} for ip, c in top]}
        break
    return result


def collect_telemetry():
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "system": platform.system(),
        "platform": platform.platform(),
        "os_pretty": os_pretty_name(),
        "kernel": platform.release(),
        "release": platform.release(),
        "python": platform.python_version(),
        "primary_ip": primary_ip(),
        "ipv4": all_ipv4(),
        "uptime_seconds": uptime_seconds(),
        "logged_in_users": logged_in_users(),
        "resources": resources(),
        "network": network_sockets(),
        "security": recent_auth_failures(),
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


def get(server, path, token, params=None):
    url = server.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, method="GET")
    request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="replace")
            return True, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return False, str(exc)


# ── endpoint isolation ───────────────────────────────────────────────

ISOLATION_COMMENT = "AUTOSOC_ISOLATION"


def _server_host(server):
    return urllib.parse.urlparse(server if "://" in server else "http://" + server).hostname or ""


def build_isolation_commands(server_ip):
    """iptables rules that cut the host off the network but keep the AutoSOC
    server reachable (so isolation can be released remotely). Returned as a
    list so the logic is testable without touching the firewall."""
    tag = ["-m", "comment", "--comment", ISOLATION_COMMENT]
    rules = [
        ["-A", "INPUT", "-i", "lo", *tag, "-j", "ACCEPT"],
        ["-A", "OUTPUT", "-o", "lo", *tag, "-j", "ACCEPT"],
        ["-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", *tag, "-j", "ACCEPT"],
        ["-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", *tag, "-j", "ACCEPT"],
    ]
    if server_ip:
        rules.append(["-A", "OUTPUT", "-d", server_ip, *tag, "-j", "ACCEPT"])
        rules.append(["-A", "INPUT", "-s", server_ip, *tag, "-j", "ACCEPT"])
    # DNS so the server hostname keeps resolving.
    rules.append(["-A", "OUTPUT", "-p", "udp", "--dport", "53", *tag, "-j", "ACCEPT"])
    # Everything else is dropped.
    rules.append(["-A", "OUTPUT", *tag, "-j", "DROP"])
    rules.append(["-A", "INPUT", *tag, "-j", "DROP"])
    return rules


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def isolate_host(server):
    if os.name == "nt":
        res = _run_check(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                          "blockinbound,blockoutbound"])
        return ("done", "Windows firewall set to block inbound+outbound.") if res else \
               ("failed", "netsh failed (run the agent as Administrator).")
    if not _is_root():
        return "failed", "Isolation needs root. Run the agent with sudo."
    server_ip = _resolve(_server_host(server))
    unisolate_host(server)  # clear any prior isolation rules first
    for rule in build_isolation_commands(server_ip):
        _run(["iptables", *rule])
    return "done", f"Host isolated via iptables (AutoSOC server {server_ip} kept reachable)."


def unisolate_host(server):
    if os.name == "nt":
        _run_check(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                    "blockinbound,allowoutbound"])
        return "done", "Windows firewall policy restored."
    if not _is_root():
        return "failed", "Release needs root. Run the agent with sudo."
    # Delete every rule tagged with our comment, on every chain.
    for _ in range(40):
        out = _run(["iptables", "-S"])
        target = None
        for line in out.splitlines():
            if ISOLATION_COMMENT in line and line.startswith("-A "):
                target = line[3:].split()
                break
        if not target:
            break
        _run(["iptables", "-D", *target])
    return "done", "Network isolation released."


def _resolve(host):
    try:
        return socket.gethostbyname(host) if host else ""
    except OSError:
        return host


def _run_check(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def execute_command(server, command):
    name = command.get("command")
    if name == "isolate":
        return isolate_host(server)
    if name == "unisolate":
        return unisolate_host(server)
    return "failed", f"Unknown command: {name}"


def poll_and_execute(server, token, agent_id):
    ok, data = get(server, "/api/v1/commands", token, params={"agent_id": agent_id})
    if not ok or not isinstance(data, dict):
        return
    for command in data.get("commands", []):
        try:
            status, result = execute_command(server, command)
        except (OSError, subprocess.SubprocessError) as exc:
            status, result = "failed", str(exc)
        print(f"[autosoc-agent] command {command.get('command')} -> {status}: {result}")
        post(server, "/api/v1/command_result", token,
             {"agent_id": agent_id, "command_id": command.get("id"), "status": status, "result": result})


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

        # Pull and run any pending commands (e.g. network isolation).
        poll_and_execute(args.server, args.token, agent_id)

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
