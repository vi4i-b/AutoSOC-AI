"""URL-structure heuristics — the offline core of phishing detection.

These checks need no network access and catch a large share of phishing URLs:
IP-literal hosts, punycode/IDN homographs, deceptive subdomains, brand
keywords placed off-domain, URL shorteners, `@`-tricks, excessive length, and
suspicious TLDs.
"""

import ipaddress
import re
from urllib.parse import urlparse, unquote

from autosoc.phishing.signals import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SignalSet,
)

# TLDs disproportionately abused for phishing/malware (free or cheap registrations).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "ml", "cf", "ga", "tk", "work", "click",
    "link", "country", "kim", "science", "party", "review", "trade", "date",
    "loan", "racing", "win", "download", "stream", "cam", "rest", "quest",
    "cyou", "sbs", "lol", "monster", "buzz",
}

# Common URL-shortener hosts (they hide the true destination).
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc",
    "bl.ink", "s.id", "v.gd", "clck.ru", "u.to", "shorte.st",
}

# Brands frequently impersonated in phishing.
IMPERSONATED_BRANDS = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp", "meta",
    "linkedin", "dhl", "fedex", "ups", "usps", "coinbase", "binance", "metamask",
    "steam", "roblox", "wellsfargo", "chase", "bankofamerica", "citibank",
    "hsbc", "santander", "revolut", "wise", "sberbank", "tinkoff", "kapital",
    "pasha", "instagr",
}

SENSITIVE_PATH_WORDS = {
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "confirm", "webscr", "banking", "password", "recover", "unlock", "billing",
    "wallet", "authenticate", "session", "validate",
}

_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    return url


def _host_is_ip(host: str) -> bool:
    if _IP_HOST_RE.match(host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.ip_address(host[1:-1])
            return True
        except ValueError:
            return False
    return False


def _has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def _has_mixed_script(host: str) -> bool:
    """Latin letters mixed with Cyrillic/Greek look-alikes in one host."""
    has_latin = any("a" <= ch.lower() <= "z" for ch in host)
    has_confusable = any(
        "Ѐ" <= ch <= "ӿ" or "Ͱ" <= ch <= "Ͽ" for ch in host
    )
    return has_latin and has_confusable


def _registered_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(raw_url: str) -> SignalSet:
    signals = SignalSet()
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    path = unquote(parsed.path or "")
    full = url.lower()

    if not host:
        signals.add("URL", "Unparseable URL", "The URL could not be parsed into a host.",
                    SEVERITY_HIGH, hit=True)
        return signals

    # Scheme
    if scheme == "https":
        signals.add("URL", "HTTPS scheme", "The URL uses HTTPS.", SEVERITY_LOW, hit=False)
    else:
        signals.add("URL", "No HTTPS", f"The URL uses '{scheme}' instead of HTTPS; credentials would travel unencrypted.",
                    SEVERITY_MEDIUM, hit=True)

    # IP-literal host
    if _host_is_ip(host):
        signals.add("URL", "IP address host",
                    f"The host is a raw IP ({host}) instead of a domain name — common in phishing.",
                    SEVERITY_HIGH, hit=True)

    # Punycode / homograph
    if _has_punycode(host):
        signals.add("URL", "Punycode host",
                    f"The host uses punycode (xn--) labels ({host}); it may impersonate a real brand via look-alike characters.",
                    SEVERITY_HIGH, hit=True)
    if _has_mixed_script(host):
        signals.add("URL", "Mixed-script host",
                    "The host mixes Latin with Cyrillic/Greek look-alike characters (homograph attack).",
                    SEVERITY_CRITICAL, hit=True)

    # userinfo (@) trick
    if parsed.username or "@" in (parsed.netloc or ""):
        signals.add("URL", "Embedded credentials / @ trick",
                    "The URL contains '@'; the real destination is whatever follows it, which hides the true host.",
                    SEVERITY_HIGH, hit=True)

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        signals.add("URL", "Non-standard port",
                    f"The URL targets port {parsed.port}, unusual for a legitimate public site.",
                    SEVERITY_MEDIUM, hit=True)

    # Subdomain depth
    labels = host.split(".")
    subdomain_depth = max(len(labels) - 2, 0)
    if subdomain_depth >= 3:
        signals.add("URL", "Deep subdomains",
                    f"The host has {subdomain_depth} subdomain levels; attackers stack subdomains to look legitimate.",
                    SEVERITY_MEDIUM, hit=True)

    # Hyphen-heavy host
    if host.count("-") >= 3:
        signals.add("URL", "Hyphen-heavy host",
                    "The host contains many hyphens, a common trait of generated phishing domains.",
                    SEVERITY_LOW, hit=True)

    # URL length
    if len(url) >= 100:
        signals.add("URL", "Very long URL",
                    f"The URL is {len(url)} characters long; long URLs often hide the true destination.",
                    SEVERITY_LOW, hit=True)

    # Suspicious TLD
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        signals.add("URL", "High-risk TLD",
                    f"The '.{tld}' TLD is frequently abused for phishing and malware.",
                    SEVERITY_MEDIUM, hit=True)

    # URL shortener
    registered = _registered_domain(host)
    if registered in URL_SHORTENERS:
        signals.add("URL", "URL shortener",
                    f"{registered} is a URL shortener; the real destination is hidden until the link is followed.",
                    SEVERITY_MEDIUM, hit=True)

    # Brand keyword off the registered domain (e.g. paypal.secure-login.tk)
    domain_core = registered.split(".")[0]
    off_domain = f"{host}{path}".lower()
    for brand in IMPERSONATED_BRANDS:
        if brand in off_domain and brand not in domain_core:
            signals.add("URL", "Brand look-alike",
                        f"The brand name '{brand}' appears in the URL but not as the registered domain "
                        f"({registered}); a classic impersonation pattern.",
                        SEVERITY_HIGH, hit=True)
            break

    # Sensitive action words in the path
    hit_words = sorted({word for word in SENSITIVE_PATH_WORDS if word in path.lower()})
    if hit_words:
        signals.add("URL", "Sensitive path keywords",
                    "The path contains credential/verification keywords: " + ", ".join(hit_words) + ".",
                    SEVERITY_LOW, hit=True)

    return signals


def parsed_host(raw_url: str) -> str:
    return (urlparse(normalize_url(raw_url)).hostname or "").lower()
