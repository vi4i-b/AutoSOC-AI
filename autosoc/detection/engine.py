"""Detection rule engine.

Rules are evaluated against two live streams:

  * :meth:`RuleEngine.evaluate_log` — every ingested log line (agent + syslog)
    is tested against enabled ``log_match`` rules, with sliding-window
    thresholds for brute-force-style detections.
  * :meth:`RuleEngine.evaluate_telemetry` — each agent snapshot is tested
    against ``telemetry_*`` rules (listening ports, connections vs IOC/block
    list, remote ports, process names).

When a rule fires the engine records a security event, and — per the rule —
opens an incident and/or blocks the source IP via an injected responder. A
per-(rule, subject) cooldown prevents alert floods from repeated telemetry.

The engine caches rules in memory; call :meth:`reload` after any rule change.
Instances are thread-safe (the collector serves requests from many threads).
"""

import re
import threading
import time
from collections import defaultdict, deque

from autosoc.logging_setup import get_logger

log = get_logger("detection.engine")

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DEFAULT_COOLDOWN = 300


class RuleEngine:
    def __init__(self, db, on_alert=None, responder=None, cooldown=DEFAULT_COOLDOWN):
        """``on_alert(alert_dict)`` per fire; ``responder(ip, reason)`` for auto-block."""
        self.db = db
        self.on_alert = on_alert
        self.responder = responder
        self.cooldown = cooldown
        self._lock = threading.RLock()
        self._log_rules = []
        self._telemetry_rules = []
        self._counters = defaultdict(deque)   # (rule_key, subject) -> timestamps
        self._last_fired = {}                  # (rule_key, subject) -> timestamp
        self.reload()

    # ── rule cache ───────────────────────────────────────────────────

    def reload(self):
        with self._lock:
            self._log_rules = []
            self._telemetry_rules = []
            for row in self.db.list_rules(enabled_only=True):
                rule = dict(row)
                if rule["rule_type"] == "log_match":
                    try:
                        rule["_regex"] = re.compile(rule.get("pattern") or "", re.IGNORECASE)
                    except re.error as exc:
                        log.warning("Rule %s has an invalid regex: %s", rule["rule_key"], exc)
                        continue
                    self._log_rules.append(rule)
                elif rule["rule_type"] == "telemetry_process":
                    try:
                        rule["_regex"] = re.compile(rule.get("pattern") or "", re.IGNORECASE)
                    except re.error as exc:
                        log.warning("Rule %s has an invalid regex: %s", rule["rule_key"], exc)
                        continue
                    self._telemetry_rules.append(rule)
                else:
                    rule["_ports"] = _parse_ports(rule.get("ports"))
                    self._telemetry_rules.append(rule)

    # ── log stream ───────────────────────────────────────────────────

    def evaluate_log(self, agent_id, source, message):
        if not message:
            return []
        alerts = []
        with self._lock:
            for rule in self._log_rules:
                if not rule["_regex"].search(message):
                    continue
                ip = _first_ip(message)
                subject = ip or agent_id or source or "unknown"
                threshold = int(rule.get("threshold") or 1)
                if threshold > 1:
                    if not self._threshold_met(rule, subject, threshold, int(rule.get("window_seconds") or 60)):
                        continue
                detail = f"Rule '{rule['name']}' matched a log line from {source or agent_id}: {message[:280]}"
                alert = self._fire(rule, subject, detail, source_ip=ip)
                if alert:
                    alerts.append(alert)
        return alerts

    def _threshold_met(self, rule, subject, threshold, window):
        key = (rule["rule_key"], subject)
        now = time.time()
        bucket = self._counters[key]
        bucket.append(now)
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) >= threshold

    # ── telemetry stream ─────────────────────────────────────────────

    def evaluate_telemetry(self, agent_id, telemetry):
        if not telemetry:
            return []
        network = telemetry.get("network") or {}
        listening = network.get("listening") or []
        connections = network.get("connections") or []
        processes = (telemetry.get("processes") or {}).get("top") or []
        host = telemetry.get("hostname") or agent_id

        alerts = []
        with self._lock:
            for rule in self._telemetry_rules:
                rule_type = rule["rule_type"]
                if rule_type == "telemetry_listen_port":
                    alerts += self._eval_listen_ports(rule, listening, host, agent_id)
                elif rule_type == "telemetry_conn_port":
                    alerts += self._eval_conn_ports(rule, connections, host, agent_id)
                elif rule_type == "telemetry_conn_ioc":
                    alerts += self._eval_conn_ioc(rule, connections, host, agent_id)
                elif rule_type == "telemetry_process":
                    alerts += self._eval_processes(rule, processes, host, agent_id)
        return alerts

    def _eval_listen_ports(self, rule, listening, host, agent_id):
        alerts = []
        for item in listening:
            port = _port_of(item.get("local"))
            if port in rule["_ports"]:
                subject = f"{agent_id}:{port}"
                detail = (f"{host} has a listener on suspicious port {port} "
                          f"(process: {item.get('process') or 'unknown'}, pid {item.get('pid') or '?'}).")
                alert = self._fire(rule, subject, detail)
                if alert:
                    alerts.append(alert)
        return alerts

    def _eval_conn_ports(self, rule, connections, host, agent_id):
        alerts = []
        for conn in connections:
            port = _port_of(conn.get("remote"))
            if port in rule["_ports"]:
                remote_ip = _first_ip(conn.get("remote", ""))
                subject = f"{agent_id}:{conn.get('remote')}"
                detail = (f"{host} connected to {conn.get('remote')} on C2-style port {port} "
                          f"(process: {conn.get('process') or 'unknown'}).")
                alert = self._fire(rule, subject, detail, source_ip=remote_ip)
                if alert:
                    alerts.append(alert)
        return alerts

    def _eval_conn_ioc(self, rule, connections, host, agent_id):
        alerts = []
        blocked = set(self.db.active_blocklist())
        for conn in connections:
            remote_ip = _first_ip(conn.get("remote", ""))
            if not remote_ip:
                continue
            hit = remote_ip in blocked or bool(self.db.match_iocs(remote_ip))
            if hit:
                detail = (f"{host} is connected to flagged IP {remote_ip} "
                          f"(process: {conn.get('process') or 'unknown'}). Matched block-list/IOC watchlist.")
                alert = self._fire(rule, remote_ip, detail, source_ip=remote_ip)
                if alert:
                    alerts.append(alert)
        return alerts

    def _eval_processes(self, rule, processes, host, agent_id):
        alerts = []
        for proc in processes:
            name = (proc.get("name") or "").strip()
            if name and rule["_regex"].search(name):
                subject = f"{agent_id}:{name}"
                detail = f"{host} is running a flagged process '{name}' (pid {proc.get('pid') or '?'})."
                alert = self._fire(rule, subject, detail)
                if alert:
                    alerts.append(alert)
        return alerts

    # ── firing ───────────────────────────────────────────────────────

    def _fire(self, rule, subject, detail, source_ip=None):
        key = (rule["rule_key"], subject)
        now = time.time()
        last = self._last_fired.get(key, 0)
        if now - last < self.cooldown:
            return None
        self._last_fired[key] = now

        severity = rule.get("severity") or "Medium"
        source = source_ip or subject
        self.db.add_security_event(f"rule.{rule['rule_key']}", severity, source, detail)

        incident_id = None
        if rule.get("auto_incident"):
            incident_id = self.db.create_incident(
                title=f"[{rule['name']}] {source}",
                severity=severity,
                source="detection-rule",
                summary=f"{detail}\nMITRE: {rule.get('mitre') or 'n/a'}. Rule: {rule['rule_key']}.",
                created_by="detection-engine",
                mitre=rule.get("mitre") or "",
            )

        if rule.get("auto_block") and source_ip and self.responder:
            try:
                self.responder(source_ip, f"rule:{rule['rule_key']}")
            except Exception:
                log.exception("Responder failed for %s", source_ip)

        alert = {
            "rule_key": rule["rule_key"],
            "name": rule["name"],
            "severity": severity,
            "mitre": rule.get("mitre") or "",
            "subject": subject,
            "source_ip": source_ip,
            "detail": detail,
            "incident_id": incident_id,
        }
        log.info("Rule fired: %s (%s) -> %s", rule["rule_key"], severity, subject)
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                log.exception("on_alert handler failed")
        return alert


def _parse_ports(value):
    ports = set()
    for chunk in (value or "").split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            ports.add(int(chunk))
    return ports


def _port_of(addr):
    if not addr:
        return None
    tail = str(addr).rsplit(":", 1)
    if len(tail) != 2 or not tail[1].isdigit():
        return None
    return int(tail[1])


def _first_ip(text):
    match = _IPV4_RE.search(str(text or ""))
    return match.group(0) if match else None
