"""Service-level hardening actions.

A firewall rule only filters traffic; for some ports the underlying service
should also be stopped (or restored when the operator re-allows the port).
These helpers return human-readable report strings for the UI console and
never raise — a failed command is part of the report.
"""

import os

from autosoc.system.commands import format_result, run_command

# Ports mapped to systemd units on Linux. Conservative on purpose: only
# services whose stop/start is safe and reversible.
LINUX_PORT_SERVICES = {
    445: ["smbd"],
    139: ["nmbd", "smbd"],
    21: ["vsftpd"],
    23: ["telnetd"],
}

_PS_NETBIOS_TEMPLATE = (
    "Get-WmiObject Win32_NetworkAdapterConfiguration | "
    "Where-Object {{$_.IPEnabled -eq $true}} | "
    "ForEach-Object {{$_.SetTcpipNetbios({mode})}}"
)


def attempt_service_close(port: int, service: str) -> str:
    """Stop the service behind a port after it was blocked. Returns a report ('' if nothing to do)."""
    if os.name == "nt":
        return _windows_close(int(port), service)
    if os.name == "posix":
        return _linux_set_services(int(port), service, start=False)
    return ""


def attempt_service_open(port: int, service: str) -> str:
    """Restore the service behind a port after it was allowed. Returns a report ('' if nothing to do)."""
    if os.name == "nt":
        return _windows_open(int(port), service)
    if os.name == "posix":
        return _linux_set_services(int(port), service, start=True)
    return ""


def _windows_close(port, service):
    if port == 445:
        messages = [f"[HARDEN] Port {port} ({service}) requires SMB service-level hardening.\n"]
        result = run_command(
            ["netsh", "advfirewall", "firewall", "set", "rule",
             "group=File and Printer Sharing", "new", "enable=No"]
        )
        messages.append(
            f"[HARDEN] Disable File and Printer Sharing firewall group: {format_result(result)}\n"
        )
        stop_result = run_command(["sc", "stop", "LanmanServer"])
        messages.append(
            f"[HARDEN] Stop Windows Server service (LanmanServer): {format_result(stop_result)}\n"
        )
        return "".join(messages)

    if port == 139:
        messages = [f"[HARDEN] Port {port} ({service}) requires NetBIOS over TCP/IP hardening.\n"]
        firewall_result = run_command(
            ["netsh", "advfirewall", "firewall", "set", "rule",
             "group=File and Printer Sharing", "new", "enable=No"]
        )
        messages.append(
            f"[HARDEN] Disable File and Printer Sharing firewall group: {format_result(firewall_result)}\n"
        )
        netbios_result = run_command(
            ["PowerShell", "-NoProfile", "-Command", _PS_NETBIOS_TEMPLATE.format(mode=2)]
        )
        messages.append(
            f"[HARDEN] Disable NetBIOS over TCP/IP on active adapters: {format_result(netbios_result)}\n"
        )
        return "".join(messages)

    if port == 135:
        return (
            f"[HARDEN] Port {port} ({service}) is Windows RPC Endpoint Mapper. "
            "AutoSOC keeps the firewall block, but does not stop RPC because that can break core "
            "Windows management. Verify exposure from another host and restrict the network segment.\n"
        )

    return ""


def _windows_open(port, service):
    if port == 445:
        messages = [f"[ALLOW] Restoring SMB service-level settings for Port {port}...\n"]
        res_fw = run_command(
            ["netsh", "advfirewall", "firewall", "set", "rule",
             "group=File and Printer Sharing", "new", "enable=Yes"]
        )
        messages.append(f"[ALLOW] Enable File and Printer Sharing group: {format_result(res_fw)}\n")
        res_sc = run_command(["sc", "start", "LanmanServer"])
        messages.append(
            f"[ALLOW] Start Windows Server service (LanmanServer): {format_result(res_sc)}\n"
        )
        return "".join(messages)

    if port == 139:
        messages = [f"[ALLOW] Restoring NetBIOS settings for Port {port}...\n"]
        res_fw = run_command(
            ["netsh", "advfirewall", "firewall", "set", "rule",
             "group=File and Printer Sharing", "new", "enable=Yes"]
        )
        messages.append(f"[ALLOW] Enable File and Printer Sharing group: {format_result(res_fw)}\n")
        netbios_result = run_command(
            ["PowerShell", "-NoProfile", "-Command", _PS_NETBIOS_TEMPLATE.format(mode=1)]
        )
        messages.append(
            f"[ALLOW] Enable NetBIOS over TCP/IP on active adapters: {format_result(netbios_result)}\n"
        )
        return "".join(messages)

    return ""


def _linux_set_services(port, service, start):
    units = LINUX_PORT_SERVICES.get(port)
    if not units:
        return ""

    action = "start" if start else "stop"
    label = "ALLOW" if start else "HARDEN"
    messages = [f"[{label}] Port {port} ({service}) maps to systemd unit(s): {', '.join(units)}.\n"]
    for unit in units:
        exists = run_command(["systemctl", "cat", unit])
        if not exists.ok:
            messages.append(f"[{label}] Unit {unit} is not installed, skipping.\n")
            continue
        result = run_command(["systemctl", action, unit])
        messages.append(f"[{label}] systemctl {action} {unit}: {format_result(result)}\n")
    return "".join(messages)
