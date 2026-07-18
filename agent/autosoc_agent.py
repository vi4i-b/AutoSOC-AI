#!/usr/bin/env python3
"""AutoSOC endpoint agent — standalone, stdlib only. Linux + Windows.

Copy this file to any server (or let the AutoSOC collector serve it over
``GET /agent``) and run one command. It enrolls with the collector, then
periodically reports host telemetry (hostname, OS, local IPs, uptime, running
processes) and ships new log lines.

Usage (Linux):
    sudo python3 autosoc_agent.py --server http://<collector-ip>:8787 --token <TOKEN>

Usage (Windows, elevated PowerShell):
    python autosoc_agent.py --server http://<collector-ip>:8787 --token <TOKEN>

Common flags:
    --interval N        seconds between reports (default 30)
    --once              collect and send a single report, then exit
    --log-file PATH     extra log file(s) to ship (repeatable)
    --win-channel NAME  extra Windows event channel to ship (repeatable)
    --name NAME         override the reported hostname
    --agent-id ID       override the stable agent id

Notes:
 - Only the standard library is used, so any Python 3.6+ works on either OS.
 - Log sources are OS-aware:
     * Linux  — tails /var/log/auth.log, /var/log/secure, /var/log/syslog
                (reading these usually needs root; run with sudo).
     * Windows — reads the Security, System and Application event logs via the
                built-in ``wevtutil`` (the Security channel needs an elevated
                / Administrator shell). Only events newer than the last cycle
                are shipped, tracked by EventRecordID.
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
# A pre-matched empty pattern so callers can do `(search(...) or _NULL_MATCH).group(0)`
# and uniformly get "" when there's no hit, without a branch.
_NULL_MATCH = re.compile("").match("")

DEFAULT_INTERVAL = 30
DEFAULT_LOG_FILES = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
# Windows event channels shipped by default. Security carries logon/account
# events (needs an elevated shell); System/Application carry service + app faults.
DEFAULT_WIN_CHANNELS = ["Security", "System", "Application"]
FIRST_READ_TAIL_LINES = 50
MAX_LINES_PER_FILE = 200
WIN_EVENTS_FIRST_READ = 30
WIN_EVENTS_PER_CYCLE = 120
HTTP_TIMEOUT = 15

# Windows Security event IDs worth calling out by name in the shipped message,
# and the severity they map to. Everything else falls back to the event Level.
WIN_SECURITY_EVENTS = {
    "4625": ("warn", "Failed logon"),
    "4740": ("warn", "Account locked out"),
    "4720": ("warn", "User account created"),
    "4726": ("warn", "User account deleted"),
    "4728": ("warn", "Member added to security-enabled global group"),
    "4732": ("warn", "Member added to security-enabled local group"),
    "4756": ("warn", "Member added to security-enabled universal group"),
    "4672": ("info", "Special privileges assigned to new logon"),
    "4688": ("info", "New process created"),
    "1102": ("critical", "Audit log cleared"),
    "4724": ("warn", "Password reset attempt"),
}


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


# ── windows event log ────────────────────────────────────────────────

# Windows event Level → our severity. Level 1=Critical 2=Error 3=Warning
# 4=Information 5=Verbose (0 often means "not set", treat as info).
_WIN_LEVEL_SEVERITY = {"1": "critical", "2": "warn", "3": "warn", "4": "info", "5": "info", "0": "info"}


class WindowsEventTailer:
    """Ships new Windows event-log records via the built-in ``wevtutil``.

    Per channel we remember the highest EventRecordID already sent and, each
    cycle, query only records newer than it (``EventRecordID > N``) — the
    Windows equivalent of the file tailer's byte offset. stdlib only:
    ``wevtutil`` ships with every Windows, and parsing uses ``xml.etree``.
    """

    def __init__(self, channels):
        self.channels = list(channels)
        self.last_record = {}  # channel -> highest EventRecordID shipped
        self._first_pass = set()

    def read_new(self):
        if os.name != "nt":
            return []
        entries = []
        for channel in self.channels:
            entries.extend(self._read_channel(channel))
        return entries

    def _read_channel(self, channel):
        first = channel not in self._first_pass
        self._first_pass.add(channel)
        last = self.last_record.get(channel, 0)

        if first:
            # Seed from the most recent events so we don't flood on startup.
            query = ["wevtutil", "qe", channel, "/c:%d" % WIN_EVENTS_FIRST_READ,
                     "/rd:true", "/f:xml"]
        else:
            xpath = "*[System[EventRecordID>%d]]" % last
            query = ["wevtutil", "qe", channel, "/q:%s" % xpath,
                     "/c:%d" % WIN_EVENTS_PER_CYCLE, "/rd:true", "/f:xml"]

        raw = _run(query)
        if not raw:
            return []

        events = _parse_wevtutil_xml(raw)
        entries = []
        highest = last
        for event in events:
            record_id = event["record_id"]
            if record_id > highest:
                highest = record_id
            if not first and record_id <= last:
                continue
            entries.append({
                "source": "WinEventLog:%s" % channel,
                "severity": event["severity"],
                "message": event["message"],
            })
        if highest > last:
            self.last_record[channel] = highest
        # Oldest-first so the console shows them in natural order.
        entries.reverse()
        return entries[-MAX_LINES_PER_FILE:]


def _parse_wevtutil_xml(raw):
    """Parse concatenated <Event>…</Event> blocks from ``wevtutil … /f:xml``."""
    import xml.etree.ElementTree as ET

    # wevtutil emits a stream of <Event> elements with no single root; wrap them.
    wrapped = "<Events>%s</Events>" % raw
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        return []

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    parsed = []
    for event in root.findall("%sEvent" % ns):
        system = event.find("%sSystem" % ns)
        if system is None:
            continue

        def _text(tag):
            node = system.find(ns + tag)
            return node.text if node is not None and node.text else ""

        try:
            record_id = int(_text("EventRecordID") or 0)
        except ValueError:
            record_id = 0
        event_id = ""
        eid_node = system.find("%sEventID" % ns)
        if eid_node is not None and eid_node.text:
            event_id = eid_node.text.strip()
        level = _text("Level") or "0"
        provider = ""
        prov_node = system.find("%sProvider" % ns)
        if prov_node is not None:
            provider = prov_node.get("Name", "")
        created = ""
        time_node = system.find("%sTimeCreated" % ns)
        if time_node is not None:
            created = time_node.get("SystemTime", "")

        # Prefer a named security event; otherwise fall back to the Level.
        severity, label = WIN_SECURITY_EVENTS.get(event_id, (None, ""))
        if severity is None:
            severity = _WIN_LEVEL_SEVERITY.get(level, "info")

        # Flatten EventData/UserData name=value pairs for a readable line.
        details = []
        for container in ("EventData", "UserData"):
            data = event.find(ns + container)
            if data is None:
                continue
            for child in data.iter():
                tag = child.tag.replace(ns, "")
                if tag in ("EventData", "UserData"):
                    continue
                name = child.get("Name", tag)
                value = (child.text or "").strip()
                if value and name not in ("", None):
                    details.append("%s=%s" % (name, value))

        head = "EventID %s" % event_id
        if label:
            head += " (%s)" % label
        if provider:
            head += " [%s]" % provider
        detail_str = " ".join(details[:12])
        message = ("%s %s" % (head, detail_str)).strip()
        if created:
            message = "%s | %s" % (created, message)

        parsed.append({"record_id": record_id, "event_id": event_id,
                       "severity": severity, "message": message[:2000]})
    return parsed


# ── telemetry ────────────────────────────────────────────────────────

def uptime_seconds():
    if os.name == "nt":
        try:
            import ctypes

            return int(ctypes.windll.kernel32.GetTickCount64() // 1000)
        except (OSError, AttributeError, ValueError):
            return None
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
    if os.name == "nt":
        return _windows_resources(data)
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
    _disk_root(data, "/")
    return data


def _disk_root(data, path):
    """Fill data['disk_root'] using shutil (cross-platform, stdlib)."""
    try:
        import shutil

        usage = shutil.disk_usage(path)
        data["disk_root"] = {
            "size_mb": str(usage.total // (1024 * 1024)),
            "used_mb": str(usage.used // (1024 * 1024)),
            "use_pct": "%d%%" % (round(100 * usage.used / usage.total) if usage.total else 0),
        }
    except (OSError, ValueError, ImportError):
        pass


def _windows_resources(data):
    """Windows memory via GlobalMemoryStatusEx (ctypes) + disk via shutil."""
    try:
        import ctypes

        class _MemStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = _MemStatus()
        status.dwLength = ctypes.sizeof(_MemStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            total = status.ullTotalPhys // (1024 * 1024)
            avail = status.ullAvailPhys // (1024 * 1024)
            data["mem_total_mb"] = total
            data["mem_used_mb"] = total - avail
            data["mem_load_pct"] = status.dwMemoryLoad
    except (OSError, AttributeError, ValueError):
        pass
    _disk_root(data, os.environ.get("SystemDrive", "C:") + "\\")
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
    if os.name == "nt":
        return _windows_auth_failures()
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


def _windows_auth_failures():
    """Count failed logons (Security event 4625) and their top source IPs."""
    result = {"count": 0, "top_sources": []}
    out = _run(["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]",
                "/c:400", "/rd:true", "/f:text"])
    if not out:
        return result
    counts = {}
    total = 0
    for block in out.split("Event["):
        if "4625" not in block:
            continue
        total += 1
        # The failed-logon event records the origin under "Source Network Address";
        # fall back to any IPv4 in the block if that label isn't present.
        labelled = re.search(r"Source Network Address:\s*([0-9a-fA-F:.]+)", block)
        ip = labelled.group(1) if labelled else (_IPV4_RE.search(block) or _NULL_MATCH).group(0)
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            counts[ip] = counts.get(ip, 0) + 1
    top = sorted(counts.items(), key=lambda item: -item[1])[:8]
    result = {"count": total, "top_sources": [{"ip": ip, "count": c} for ip, c in top]}
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
    # Windows: ship event-log records too (no-op on other OSes).
    win_tailer = WindowsEventTailer((args.win_channel or []) or DEFAULT_WIN_CHANNELS)

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
        logs = tailer.read_new() + win_tailer.read_new()
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
    parser.add_argument("--win-channel", action="append",
                        help="Extra Windows event channel to ship, e.g. "
                             "'Microsoft-Windows-Windows Defender/Operational' (repeatable)")
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
