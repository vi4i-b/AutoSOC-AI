"""Cross-platform firewall management.

The UI works with the small :class:`FirewallBackend` interface; the platform
specifics live in :class:`WindowsFirewall` (netsh advfirewall) and
:class:`LinuxFirewall` (iptables). All rules created by AutoSOC carry the
``AutoSOC_`` prefix so they can be recognized and removed later without
touching rules created by anything else.

Managing rules requires elevated privileges (Administrator / root); backends
report the failure message instead of raising, so callers can show it to the
operator.
"""

import ipaddress
import json
import os
import re
import shutil

from autosoc.logging_setup import get_logger
from autosoc.system.commands import format_result, run_command

log = get_logger("system.firewall")

MANUAL_RULE_PREFIX = "AutoSOC_Manual"


# ── conflicting-manager detection ────────────────────────────────────

def _service_active(unit: str) -> bool:
    """True when systemd reports ``unit`` as active. No root required; returns
    False on non-systemd hosts (systemctl missing → command fails)."""
    result = run_command(["systemctl", "is-active", unit])
    return result.stdout.strip() == "active"


def _ufw_active() -> bool:
    if _service_active("ufw"):
        return True
    if not shutil.which("ufw"):
        return False
    # `ufw status` needs root; when it works it's authoritative.
    result = run_command(["ufw", "status"])
    return "Status: active" in result.stdout


def _firewalld_active() -> bool:
    if _service_active("firewalld"):
        return True
    if not shutil.which("firewall-cmd"):
        return False
    result = run_command(["firewall-cmd", "--state"])
    return result.stdout.strip() == "running"


def active_firewall_managers() -> list:
    """Other firewall managers currently active on this host.

    AutoSOC writes raw iptables rules; when UFW or firewalld is *also* active it
    manages the same chains and can shadow AutoSOC's rules (before this app
    started inserting at the top of INPUT) or wipe them on its next reload. The
    UI surfaces this so an operator isn't misled. Best-effort, no root needed,
    never raises — any detection error simply means "not detected"."""
    if os.name != "posix":
        return []
    managers = []
    try:
        if _ufw_active():
            managers.append("ufw")
        if _firewalld_active():
            managers.append("firewalld")
    except OSError as exc:  # pragma: no cover - defensive
        log.debug("firewall-manager detection error: %s", exc)
    return managers


def firewall_conflict_warning() -> str:
    """A one-paragraph operator warning naming any active conflicting manager,
    or "" when there is no conflict."""
    managers = active_firewall_managers()
    if not managers:
        return ""
    names = " and ".join(managers)
    return (
        f"{names} is active on this host and manages the same iptables chains as "
        f"AutoSOC. AutoSOC now inserts its rules at the top of INPUT so they take "
        f"effect immediately, but a `{managers[0]} reload` or reboot will flush "
        f"them (they are runtime rules). Avoid managing the same port with both "
        f"{names} and AutoSOC."
    )


class FirewallBackend:
    """Interface implemented by every platform backend."""

    name = "none"

    def set_port_blocked(self, port: int, blocked: bool):
        """Block or unblock inbound traffic to a local port.

        Returns ``(success, rule_name, message)``. Unblocking only removes
        the AutoSOC block rule; no broad allow rule is ever created.
        """
        raise NotImplementedError

    def block_ip(self, ip: str, rule_prefix: str = "AutoSOC_Guard_Block"):
        """Drop all inbound traffic from a remote IP. Returns ``(success, rule_name, message)``."""
        raise NotImplementedError

    def blocked_ports(self) -> set:
        """Ports currently blocked by AutoSOC rules."""
        raise NotImplementedError


class WindowsFirewall(FirewallBackend):
    name = "netsh advfirewall"

    ACCESS_ERROR_MARKERS = ("access is denied", "requires elevation", "permission", "отказано")

    def _run_netsh(self, arguments):
        return run_command(["netsh", *arguments])

    def set_port_blocked(self, port, blocked):
        port = int(port)
        rule_name = f"{MANUAL_RULE_PREFIX}_{port}"
        delete_result = self._run_netsh(
            ["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        )

        if not blocked:
            combined = format_result(delete_result)
            lowered = combined.lower()
            if not delete_result.ok and any(marker in lowered for marker in self.ACCESS_ERROR_MARKERS):
                return False, rule_name, combined
            return True, rule_name, "AutoSOC block rule removed. No broad allow rule was created."

        results = []
        for protocol in ("TCP", "UDP"):
            results.append(
                self._run_netsh(
                    [
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name={rule_name}",
                        "dir=in",
                        "action=block",
                        f"protocol={protocol}",
                        f"localport={port}",
                        "profile=any",
                        "interfacetype=any",
                    ]
                )
            )

        combined = " ".join(format_result(result) for result in results)
        if all(result.ok for result in results):
            return True, rule_name, combined or "Firewall rule updated successfully."
        return False, rule_name, combined or "One or more netsh rules failed."

    def block_ip(self, ip, rule_prefix="AutoSOC_Guard_Block"):
        normalized_ip, error = _normalize_ip(ip)
        if error:
            return False, "", error

        rule_name = f"{rule_prefix}_{normalized_ip}"
        self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
        add_result = self._run_netsh(
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={normalized_ip}",
            ]
        )
        message = format_result(add_result)
        if add_result.ok:
            return True, rule_name, message or "Firewall rule added successfully."
        return False, rule_name, message

    def blocked_ports(self):
        ports = set()
        result = run_command(
            [
                "PowerShell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-NetFirewallRule -Name {MANUAL_RULE_PREFIX}_* -ErrorAction SilentlyContinue | "
                    "Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' } | "
                    "Select-Object -Property Name | ConvertTo-Json"
                ),
            ]
        )
        if not result.ok or not result.stdout.strip():
            return ports

        try:
            raw = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return ports

        rules = raw if isinstance(raw, list) else [raw]
        for rule in rules:
            rule_name = (rule or {}).get("Name", "")
            if rule_name.startswith(f"{MANUAL_RULE_PREFIX}_"):
                try:
                    ports.add(int(rule_name.rsplit("_", 1)[-1]))
                except ValueError:
                    continue
        return ports


class LinuxFirewall(FirewallBackend):
    """iptables backend (works on Ubuntu with either legacy or nft iptables).

    Rules are tagged with an ``AutoSOC_*`` comment so they can be listed and
    deleted precisely. Requires root.

    Two hard-won correctness details:

    * **Insert at the top, don't append.** A DROP appended with ``-A`` lands at
      the *bottom* of INPUT — below UFW's jump rules (``-A INPUT -j
      ufw-before-input`` etc.), which have usually already ACCEPTed the packet,
      so the AutoSOC rule never fires. We therefore ``-I INPUT 1`` so every
      AutoSOC rule sits at the very top of the chain and takes precedence over
      whatever UFW/firewalld placed below it.
    * **Loopback must be blocked explicitly for the self-scan to see it.** The
      built-in verifier scans ``127.0.0.1``. Systems (and UFW) accept loopback
      early (``-A INPUT -i lo -j ACCEPT``), so we add a dedicated
      ``-i lo --dport <port> DROP`` rule — also inserted at position 1 — so a
      local scan reports the port as filtered instead of open.

    Cleanup deletes by the rule's *full specification* (which includes the
    ``AutoSOC_*`` comment), so only rules AutoSOC created are ever removed — a
    user's or UFW's own rules are never touched.
    """

    name = "iptables"

    DPORT_RE = re.compile(r"--dport (\d+)")
    COMMENT_RE = re.compile(r'--comment "?(AutoSOC_[\w.:-]+)"?')

    # ── rule specifications (chain excluded; we always target INPUT) ──

    def _port_rule_bodies(self, port, rule_name):
        """Every iptables rule body AutoSOC creates to block one port.

        For each of TCP and UDP: a general rule (all interfaces) plus an
        explicit loopback (``-i lo``) rule, so a local 127.0.0.1 self-scan sees
        the block too. Every body carries the same AutoSOC comment so cleanup
        is exact."""
        tag = ["-m", "comment", "--comment", rule_name]
        bodies = []
        for protocol in ("tcp", "udp"):
            bodies.append(["-p", protocol, "--dport", str(port), *tag, "-j", "DROP"])
            bodies.append(["-i", "lo", "-p", protocol, "--dport", str(port), *tag, "-j", "DROP"])
        return bodies

    def _ip_rule_body(self, ip, rule_name):
        return ["-s", ip, "-m", "comment", "--comment", rule_name, "-j", "DROP"]

    # ── primitive operations ─────────────────────────────────────────

    def _insert_top(self, body):
        """Insert a rule at INPUT position 1 so it overrides UFW/firewalld
        rules, which sit lower in the chain."""
        return run_command(["iptables", "-I", "INPUT", "1", *body])

    def _delete_all(self, body):
        """Delete every copy of exactly this rule (iptables allows duplicates).

        Matching is by the full spec — which includes the ``AutoSOC_*``
        comment — so only our own rules are removed; user/UFW rules are safe.
        Insert and delete use the identical body, so the specs always match."""
        for _ in range(20):
            result = run_command(["iptables", "-D", "INPUT", *body])
            if not result.ok:
                break

    def set_port_blocked(self, port, blocked):
        port = int(port)
        rule_name = f"{MANUAL_RULE_PREFIX}_{port}"
        bodies = self._port_rule_bodies(port, rule_name)

        # Idempotent: always clear any existing AutoSOC rules for this port
        # first. When unblocking, that is the entire job.
        for body in bodies:
            self._delete_all(body)

        if not blocked:
            return True, rule_name, "AutoSOC block rules removed. No broad allow rule was created."

        success = True
        messages = []
        # Insert in reverse so the first body ends up highest after successive
        # position-1 inserts (purely cosmetic; all are DROP and above UFW).
        for body in reversed(bodies):
            result = self._insert_top(body)
            if not result.ok:
                success = False
                messages.append(format_result(result))

        if success:
            message = ("iptables DROP rules inserted at the top of INPUT for TCP+UDP "
                       "(including loopback), overriding UFW.")
        else:
            message = " ".join(messages) or "One or more iptables rules failed."
            log.warning("iptables port block failed for %s: %s", port, message)
        return success, rule_name, message

    def block_ip(self, ip, rule_prefix="AutoSOC_Guard_Block"):
        normalized_ip, error = _normalize_ip(ip)
        if error:
            return False, "", error

        rule_name = f"{rule_prefix}_{normalized_ip}"
        body = self._ip_rule_body(normalized_ip, rule_name)
        self._delete_all(body)
        result = self._insert_top(body)
        message = format_result(result)
        if result.ok:
            return True, rule_name, message if message != "Ok." else "iptables DROP rule inserted at top of INPUT."
        log.warning("iptables IP block failed for %s: %s", normalized_ip, message)
        return False, rule_name, message

    def blocked_ports(self):
        ports = set()
        result = run_command(["iptables", "-S", "INPUT"])
        if not result.ok:
            return ports
        for line in result.stdout.splitlines():
            if f"{MANUAL_RULE_PREFIX}_" not in line or "DROP" not in line:
                continue
            match = self.DPORT_RE.search(line)
            if match:
                ports.add(int(match.group(1)))
        return ports


def get_firewall() -> FirewallBackend | None:
    """Backend for the current platform, or None when unsupported."""
    if os.name == "nt":
        return WindowsFirewall()
    if os.name == "posix":
        return LinuxFirewall()
    return None


def _normalize_ip(ip):
    try:
        return str(ipaddress.ip_address(str(ip).strip())), None
    except ValueError:
        return None, f"Invalid IP address: {ip}"
