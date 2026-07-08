"""Local network information helpers."""

import ipaddress
import os
import re
import socket

from autosoc.system.commands import run_command

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def local_ip_addresses() -> set:
    """All IP addresses assigned to this host, including loopback."""
    addresses = {"127.0.0.1", "::1"}
    hostname = socket.gethostname()
    try:
        for item in socket.getaddrinfo(hostname, None):
            addresses.add(item[4][0])
    except OSError:
        pass
    try:
        addresses.update(socket.gethostbyname_ex(hostname)[2])
    except OSError:
        pass

    if os.name == "nt":
        result = run_command(["ipconfig"])
        for line in result.stdout.splitlines():
            if "IPv4" not in line or ":" not in line:
                continue
            candidate = line.split(":", 1)[1].strip().split("(", 1)[0].strip()
            _add_if_valid(addresses, candidate)
    else:
        result = run_command(["ip", "-o", "addr", "show"])
        for line in result.stdout.splitlines():
            for candidate in _IPV4_RE.findall(line):
                _add_if_valid(addresses, candidate)

    return addresses


def target_appears_remote(target: str) -> bool:
    """True when the scan target does not resolve to this machine."""
    target = (target or "").strip()
    if not target or "/" in target:
        return False

    local_ips = local_ip_addresses()
    try:
        target_ip = ipaddress.ip_address(target)
        return not target_ip.is_loopback and str(target_ip) not in local_ips
    except ValueError:
        pass

    if target.lower() in {"localhost", socket.gethostname().lower()}:
        return False

    try:
        resolved_ips = {item[4][0] for item in socket.getaddrinfo(target, None)}
    except OSError:
        return False

    return bool(resolved_ips) and not any(ip in local_ips for ip in resolved_ips)


def _add_if_valid(addresses: set, candidate: str) -> None:
    try:
        addresses.add(str(ipaddress.ip_address(candidate)))
    except ValueError:
        pass
