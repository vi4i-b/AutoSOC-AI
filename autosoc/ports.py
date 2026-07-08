"""The single source of truth for TCP ports AutoSOC tracks."""

TRACKED_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MS-SQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports blocked by default when "Harden Risky" runs without scan data.
DEFAULT_RISKY_PORTS = [21, 23, 445, 3389, 5900, 6379, 27017, 3306, 1433, 1521]


def service_name(port, default="Unknown"):
    try:
        return TRACKED_PORTS.get(int(port), default)
    except (TypeError, ValueError):
        return default
