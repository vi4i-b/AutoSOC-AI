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

from autosoc.logging_setup import get_logger
from autosoc.system.commands import format_result, run_command

log = get_logger("system.firewall")

MANUAL_RULE_PREFIX = "AutoSOC_Manual"


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
    """

    name = "iptables"

    DPORT_RE = re.compile(r"--dport (\d+)")
    COMMENT_RE = re.compile(r'--comment "?(AutoSOC_[\w.:-]+)"?')

    def _port_rule_args(self, port, protocol, rule_name):
        return [
            "INPUT",
            "-p",
            protocol,
            "--dport",
            str(port),
            "-m",
            "comment",
            "--comment",
            rule_name,
            "-j",
            "DROP",
        ]

    def _ip_rule_args(self, ip, rule_name):
        return ["INPUT", "-s", ip, "-m", "comment", "--comment", rule_name, "-j", "DROP"]

    def _delete_matching(self, rule_args):
        """Delete every copy of a rule (iptables allows duplicates)."""
        for _ in range(10):
            result = run_command(["iptables", "-D", *rule_args])
            if not result.ok:
                break

    def set_port_blocked(self, port, blocked):
        port = int(port)
        rule_name = f"{MANUAL_RULE_PREFIX}_{port}"

        messages = []
        success = True
        for protocol in ("tcp", "udp"):
            rule_args = self._port_rule_args(port, protocol, rule_name)
            self._delete_matching(rule_args)
            if blocked:
                result = run_command(["iptables", "-A", *rule_args])
                if not result.ok:
                    success = False
                    messages.append(format_result(result))

        if blocked:
            message = " ".join(messages) or "iptables DROP rules added for TCP and UDP."
            if not success:
                log.warning("iptables port block failed for %s: %s", port, message)
            return success, rule_name, message
        return True, rule_name, "AutoSOC block rule removed. No broad allow rule was created."

    def block_ip(self, ip, rule_prefix="AutoSOC_Guard_Block"):
        normalized_ip, error = _normalize_ip(ip)
        if error:
            return False, "", error

        rule_name = f"{rule_prefix}_{normalized_ip}"
        rule_args = self._ip_rule_args(normalized_ip, rule_name)
        self._delete_matching(rule_args)
        result = run_command(["iptables", "-I", *rule_args])
        message = format_result(result)
        if result.ok:
            return True, rule_name, message if message != "Ok." else "iptables DROP rule added."
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
