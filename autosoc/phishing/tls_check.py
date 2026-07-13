"""TLS certificate inspection.

Presence of HTTPS says nothing on its own (phishing sites get free certs too),
but the certificate *details* are informative: hostname mismatch, expiry,
and a very freshly issued certificate on a look-alike domain are all signals.
"""

import datetime
import socket
import ssl
from urllib.parse import urlparse

from autosoc.phishing.signals import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, SignalSet
from autosoc.phishing.url_features import normalize_url

TLS_TIMEOUT = 6


def _parse_cert_time(value):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            continue
    return None


def analyze_tls(raw_url: str) -> SignalSet:
    signals = SignalSet()
    parsed = urlparse(normalize_url(raw_url))
    if parsed.scheme != "https":
        return signals

    host = parsed.hostname
    if not host:
        return signals
    port = parsed.port or 443

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        signals.add("TLS", "Certificate verification failed",
                    f"The TLS certificate did not validate: {exc.verify_message or exc}.",
                    SEVERITY_HIGH, hit=True)
        return signals
    except (socket.timeout, socket.gaierror, ConnectionError, OSError, ssl.SSLError) as exc:
        signals.add("TLS", "TLS handshake failed",
                    f"Could not complete a TLS handshake with {host}: {exc}.",
                    SEVERITY_LOW, hit=True)
        return signals

    if not cert:
        signals.add("TLS", "No certificate details",
                    "The server presented no inspectable certificate.", SEVERITY_LOW, hit=True)
        return signals

    now = datetime.datetime.utcnow()

    # Expiry / validity window
    not_after = _parse_cert_time(cert.get("notAfter"))
    not_before = _parse_cert_time(cert.get("notBefore"))
    if not_after and now > not_after:
        signals.add("TLS", "Expired certificate",
                    f"The certificate expired on {cert.get('notAfter')}.", SEVERITY_HIGH, hit=True)
    elif not_before:
        age_days = (now - not_before).days
        if age_days < 14:
            signals.add("TLS", "Very new certificate",
                        f"The certificate was issued {max(age_days, 0)} day(s) ago; phishing domains often use just-issued certs.",
                        SEVERITY_MEDIUM, hit=True)
        else:
            signals.add("TLS", "Valid certificate",
                        f"Certificate is valid and {age_days} day(s) old.", SEVERITY_LOW, hit=False)

    # Issuer
    issuer = dict(item for entry in cert.get("issuer", ()) for item in entry)
    issuer_org = issuer.get("organizationName") or issuer.get("commonName") or "unknown issuer"

    # Hostname coverage
    san = [value for typ, value in cert.get("subjectAltName", ()) if typ == "DNS"]
    if san:
        covered = any(_host_matches(host, pattern) for pattern in san)
        if not covered:
            signals.add("TLS", "Hostname not in certificate",
                        f"{host} is not covered by the certificate's names ({', '.join(san[:4])}).",
                        SEVERITY_HIGH, hit=True)
        else:
            signals.add("TLS", "Issuer",
                        f"Certificate issued by {issuer_org}, covering the requested host.",
                        SEVERITY_LOW, hit=False)

    return signals


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.split(".", 1)[-1] == pattern[2:] or host == pattern[2:]
    return host == pattern
