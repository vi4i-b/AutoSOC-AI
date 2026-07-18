"""Forward ingested logs to an operator-chosen destination.

The local SQLite store is always the primary system of record. On top of that,
an analyst can pick *where else* every ingested log should land:

  * an external **syslog** collector (SIEM, Graylog, rsyslog, a FortiAnalyzer…)
    over UDP in RFC 3164 format, and/or
  * a local **file** (one JSON object per line) for a durable, greppable
    archive or hand-off to another pipeline.

Both are optional and independent; either, both, or neither can be enabled.
Configuration lives in ``app_settings`` so it survives restarts:

  log_forward_syslog   "host:port"   (empty = off; default UDP port 514)
  log_forward_file     "/path/file"  (empty = off)
  log_retention_days   "N"           (0 = keep forever; purge handled elsewhere)

Forwarding never raises into the ingestion path — a broken destination must not
stop logs being stored. Failures are counted and surfaced in the UI instead.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime

from autosoc.logging_setup import get_logger

log = get_logger("system.log_forwarder")

# RFC 3164 facility/severity → PRI. We use facility 13 (log audit) and map our
# coarse severities to syslog levels.
_SYSLOG_FACILITY = 13
_SEVERITY_TO_SYSLOG = {"critical": 2, "high": 3, "warn": 4, "warning": 4, "info": 6, "debug": 7}

SETTING_SYSLOG = "log_forward_syslog"
SETTING_FILE = "log_forward_file"
SETTING_RETENTION = "log_retention_days"


def parse_host_port(value, default_port=514):
    """Parse 'host', 'host:port' or '' → (host, port) or (None, None)."""
    value = (value or "").strip()
    if not value:
        return None, None
    if ":" in value:
        host, _, port = value.rpartition(":")
        host = host.strip()
        try:
            return (host or None), int(port)
        except ValueError:
            return (host or None), default_port
    return value, default_port


class LogForwarder:
    """Reads its destination config from the DB settings and forwards entries.

    Thread-safe: the collector runs on several handler threads, so the UDP
    socket and the file handle are guarded by a lock. Call :meth:`reload` after
    changing settings so the change takes effect without an app restart.
    """

    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._sock = None
        self.syslog_target = (None, None)
        self.file_path = ""
        self.sent = 0
        self.failed = 0
        self.reload()

    # ── configuration ────────────────────────────────────────────────

    def reload(self):
        with self._lock:
            self.syslog_target = parse_host_port(self.db.get_setting(SETTING_SYSLOG, ""))
            self.file_path = (self.db.get_setting(SETTING_FILE, "") or "").strip()
            if self._sock is None and self.syslog_target[0]:
                try:
                    self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                except OSError as exc:
                    log.warning("Could not create forwarding socket: %s", exc)
                    self._sock = None

    @property
    def enabled(self) -> bool:
        return bool(self.syslog_target[0]) or bool(self.file_path)

    def status(self) -> dict:
        return {
            "syslog": (f"{self.syslog_target[0]}:{self.syslog_target[1]}"
                       if self.syslog_target[0] else ""),
            "file": self.file_path,
            "enabled": self.enabled,
            "sent": self.sent,
            "failed": self.failed,
        }

    # ── forwarding ───────────────────────────────────────────────────

    def forward(self, message, agent_id="", source="", severity="info"):
        """Best-effort fan-out to the configured destinations. Never raises."""
        if not self.enabled:
            return
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "agent_id": agent_id,
            "source": source,
            "severity": severity,
            "message": message,
        }
        ok = True
        if self.syslog_target[0]:
            ok = self._send_syslog(entry) and ok
        if self.file_path:
            ok = self._append_file(entry) and ok
        with self._lock:
            if ok:
                self.sent += 1
            else:
                self.failed += 1

    def _send_syslog(self, entry) -> bool:
        host, port = self.syslog_target
        if not host or self._sock is None:
            return False
        level = _SEVERITY_TO_SYSLOG.get(str(entry["severity"]).lower(), 6)
        pri = _SYSLOG_FACILITY * 8 + level
        stamp = datetime.now().strftime("%b %d %H:%M:%S")
        host_tag = socket.gethostname()
        tag = (entry.get("source") or "autosoc").replace(" ", "_")[:32]
        content = entry["message"]
        if entry.get("agent_id"):
            content = f"agent={entry['agent_id']} {content}"
        packet = f"<{pri}>{stamp} {host_tag} {tag}: {content}".encode("utf-8", "replace")[:2000]
        try:
            with self._lock:
                self._sock.sendto(packet, (host, port))
            return True
        except OSError as exc:
            log.debug("syslog forward to %s:%s failed: %s", host, port, exc)
            return False

    def _append_file(self, entry) -> bool:
        try:
            directory = os.path.dirname(self.file_path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, exist_ok=True)
            with self._lock:
                with open(self.file_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return True
        except OSError as exc:
            log.debug("file forward to %s failed: %s", self.file_path, exc)
            return False

    def close(self):
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
