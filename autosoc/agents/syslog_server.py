"""Agentless syslog ingestion.

Network devices that can't run the AutoSOC agent — FortiGate, Palo Alto,
switches, routers, Linux boxes — can forward **syslog** instead. This service
listens on UDP (default :5514, a non-privileged port), parses RFC 3164 / 5424
framing, stores each message in ``ingested_logs``, and runs lightweight
brute-force detection so repeated login failures (sshd or FortiGate) raise a
security event.

Point a FortiGate here with:
    config log syslogd setting
        set status enable
        set server <autosoc-ip>
        set port 5514
        set mode udp
    end
"""

import os
import re
import socketserver
import threading

from autosoc.logging_setup import get_logger
from autosoc.system.log_monitor import BruteForceTracker

log = get_logger("agents.syslog")

DEFAULT_SYSLOG_PORT = 5514

# <PRI>VERSION? TIMESTAMP HOST TAG: MESSAGE — we only need PRI + the tail.
_PRI_RE = re.compile(r"^<(\d{1,3})>")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_RFC3164_HEAD_RE = re.compile(
    r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?(?P<host>[\w.\-]+)\s+(?P<rest>.*)$"
)

# Login-failure fingerprints across common sources.
_FAILURE_PATTERNS = [
    re.compile(r"Failed password for .+ from (?P<ip>\S+)"),
    re.compile(r"Invalid user .+ from (?P<ip>\S+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>[\w.:-]+)"),
    # FortiGate admin/user login failure: action=login status=failed ... srcip=x.x.x.x
    re.compile(r"action=\"?login\"?.*status=\"?failed\"?.*srcip=\"?(?P<ip>[\d.]+)"),
    re.compile(r"srcip=\"?(?P<ip>[\d.]+)\"?.*action=\"?login\"?.*status=\"?failed"),
    re.compile(r"logdesc=\"?[^\"]*login failed", re.IGNORECASE),
]


def severity_from_pri(pri):
    """Map syslog PRI severity (0 emerg .. 7 debug) to our labels."""
    sev = pri & 0x07
    if sev <= 2:
        return "critical"
    if sev == 3:
        return "High"
    if sev == 4:
        return "warn"
    return "info"


def parse_syslog(raw, sender_ip):
    """Return (host, severity, message) from a raw syslog datagram."""
    text = raw.decode("utf-8", errors="replace").strip()
    severity = "info"
    host = sender_ip
    body = text

    match = _PRI_RE.match(text)
    if match:
        try:
            severity = severity_from_pri(int(match.group(1)))
        except ValueError:
            pass
        text = text[match.end():]
        body = text
        # Only trust an embedded hostname when this is real syslog framing
        # (a PRI was present); otherwise fall back to the sender IP.
        head = _RFC3164_HEAD_RE.match(text)
        if head and head.group("host"):
            candidate = head.group("host")
            # RFC5424 puts a version digit first; ignore that as a "host".
            if not candidate.isdigit():
                host = candidate
                body = head.group("rest")
    return host, severity, body.strip()


class SyslogService:
    def __init__(self, db, on_detection=None, host="0.0.0.0", port=None,
                 threshold=5, window_seconds=60, engine=None, forwarder=None):
        self.db = db
        self.on_detection = on_detection
        self.engine = engine
        # Optional external forwarding of every syslog line (see LogForwarder).
        self.forwarder = forwarder
        self.host = host
        self.port = int(port) if port is not None else int(os.getenv("AUTOSOC_SYSLOG_PORT") or DEFAULT_SYSLOG_PORT)
        self.tracker = BruteForceTracker(threshold=threshold, window_seconds=window_seconds)
        self._server = None
        self._thread = None

    @property
    def running(self):
        return self._server is not None

    def address(self):
        return self.host, self.port

    def start(self):
        if self.running:
            return True, f"Syslog already listening on {self.host}:{self.port}/udp"

        service = self

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request[0]
                service._process(data, self.client_address[0])

        try:
            server = socketserver.ThreadingUDPServer((self.host, self.port), _Handler)
        except OSError as exc:
            log.warning("Syslog failed to bind %s:%s — %s", self.host, self.port, exc)
            return False, f"Could not bind {self.host}:{self.port}/udp: {exc}"

        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="AutoSOCSyslog", daemon=True)
        self._thread.start()
        log.info("Syslog listening on %s:%s/udp", self.host, self.port)
        return True, f"Syslog listening on {self.host}:{self.port}/udp"

    def stop(self):
        if not self.running:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception as exc:
            log.debug("Syslog stop error: %s", exc)
        finally:
            self._server = None
            self._thread = None
        log.info("Syslog stopped")

    def _process(self, data, sender_ip):
        try:
            host, severity, message = parse_syslog(data, sender_ip)
            if not message:
                return
            self.db.add_ingested_log(message[:2000], agent_id=host, source="syslog", severity=severity)
            if self.forwarder is not None and self.forwarder.enabled:
                self.forwarder.forward(message[:2000], agent_id=host, source="syslog", severity=severity)
            if self.engine is not None:
                try:
                    self.engine.evaluate_log(host, "syslog", message)
                except Exception:
                    log.exception("Rule engine evaluation failed for syslog")
            self._detect(host, sender_ip, message)
        except Exception as exc:
            log.debug("Syslog processing error: %s", exc)

    def _detect(self, host, sender_ip, message):
        source_ip = self._failure_source(message)
        if not source_ip:
            return
        detection = self.tracker.register_failure(source_ip)
        if not detection:
            return
        details = (f"{detection['attempt_count']} failed logins from {source_ip} within "
                   f"{detection['window_seconds']}s (via syslog from {host}).")
        self.db.add_security_event("syslog_bruteforce", "High", source_ip, details)
        if self.on_detection:
            detection["service"] = "Syslog Login"
            detection["reporter"] = host
            try:
                self.on_detection(detection)
            except Exception:
                log.exception("syslog on_detection callback failed")

    @staticmethod
    def _failure_source(message):
        for pattern in _FAILURE_PATTERNS:
            match = pattern.search(message)
            if match and "ip" in match.groupdict() and match.group("ip"):
                found = _IPV4_RE.search(match.group("ip"))
                if found:
                    return found.group(0)
        return None
