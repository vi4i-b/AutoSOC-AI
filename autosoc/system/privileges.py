"""Cross-platform privilege checks."""

import ctypes
import os


def is_admin() -> bool:
    """True when the process can manage the firewall and system services."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def privilege_hint() -> str:
    """Human-readable instruction for obtaining the required privileges."""
    if os.name == "nt":
        return "Run AutoSOC as Administrator to manage firewall rules."
    return "Run AutoSOC with sudo (e.g. `sudo -E python3 main.py`) to manage firewall rules."
