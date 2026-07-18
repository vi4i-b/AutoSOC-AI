"""Multi-source threat-intel enrichment with a normalized verdict.

Design notes:
 - Each provider is split into a *pure* parser (``_parse_*`` — canned JSON in,
   :class:`Verdict` out) and a thin network wrapper. The parsers carry all the
   logic and are unit-tested without any network access.
 - Network calls go through :func:`autosoc.net.retry_request` (bounded
   exponential backoff on transient failures) with a hard timeout, and any API
   key is scrubbed from error strings before it can reach a log or the UI.
 - Only providers with a configured key are consulted; everything degrades to
   "not configured" rather than failing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

import requests

from autosoc.logging_setup import get_logger
from autosoc.net import RetryError, retry_request

log = get_logger("intel.enrichment")

HTTP_TIMEOUT = 12

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def classify_indicator(value: str) -> str:
    """Best-effort indicator type: ip | url | domain | hash | email | unknown."""
    value = (value or "").strip()
    if not value:
        return "unknown"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(value):
        return "hash"
    if _EMAIL_RE.match(value):
        return "email"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


@dataclass
class Verdict:
    """One provider's normalized answer about one indicator."""

    provider: str
    indicator: str
    ok: bool = True                 # the query itself succeeded
    malicious: "bool | None" = None  # True/False verdict, or None if unknown
    score: str = ""                 # short headline metric, e.g. "5/94" or "88%"
    detail: str = ""                # human-readable summary
    link: str = ""                  # a URL an analyst can open to dig deeper
    error: str = ""


def _scrub(text: str, *secrets: str) -> str:
    out = str(text)
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    return out


# ── pure parsers (unit-tested, no network) ───────────────────────────

def _parse_virustotal(indicator: str, data: dict) -> Verdict:
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    verdict = Verdict(provider="VirusTotal", indicator=indicator,
                      link=f"https://www.virustotal.com/gui/search/{indicator}")
    verdict.malicious = (malicious + suspicious) > 0
    verdict.score = f"{malicious + suspicious}/{total}" if total else "0/0"
    verdict.detail = (f"{malicious} engines flagged malicious, {suspicious} suspicious "
                      f"of {total}.") if total else "No analysis results yet."
    return verdict


def _parse_abuseipdb(indicator: str, data: dict) -> Verdict:
    payload = data.get("data") or {}
    confidence = int(payload.get("abuseConfidenceScore", 0))
    reports = int(payload.get("totalReports", 0))
    country = payload.get("countryCode") or "?"
    isp = payload.get("isp") or ""
    verdict = Verdict(provider="AbuseIPDB", indicator=indicator,
                      link=f"https://www.abuseipdb.com/check/{indicator}")
    verdict.malicious = confidence >= 50
    verdict.score = f"{confidence}%"
    verdict.detail = (f"Abuse confidence {confidence}% from {reports} report(s); "
                      f"{country} {isp}".strip())
    return verdict


def _parse_otx(indicator: str, data: dict) -> Verdict:
    pulse_info = data.get("pulse_info") or {}
    count = int(pulse_info.get("count", 0))
    verdict = Verdict(provider="AlienVault OTX", indicator=indicator,
                      link=f"https://otx.alienvault.com/indicator/domain/{indicator}")
    verdict.malicious = count > 0
    verdict.score = f"{count} pulses"
    names = [p.get("name", "") for p in (pulse_info.get("pulses") or [])[:3] if p.get("name")]
    verdict.detail = (f"Referenced in {count} community threat pulse(s)."
                      + (f" e.g. {', '.join(names)}" if names else "")) if count \
        else "Not referenced in any OTX threat pulse."
    return verdict


# ── enricher ─────────────────────────────────────────────────────────

# Setting keys for provider API credentials.
SETTING_VT = "vt_api_key"
SETTING_ABUSEIPDB = "abuseipdb_api_key"
SETTING_OTX = "otx_api_key"


@dataclass
class ThreatIntelEnricher:
    db: object
    session: "requests.Session | None" = field(default=None)

    def __post_init__(self):
        self.session = self.session or requests.Session()

    # -- key access --
    def _key(self, setting: str) -> str:
        return (self.db.get_setting(setting, "") or "").strip()

    def configured_providers(self) -> list[str]:
        names = []
        if self._key(SETTING_VT):
            names.append("VirusTotal")
        if self._key(SETTING_ABUSEIPDB):
            names.append("AbuseIPDB")
        if self._key(SETTING_OTX):
            names.append("AlienVault OTX")
        return names

    def enrich(self, indicator: str, ioc_type: str = "") -> list[Verdict]:
        """Query every applicable, configured provider for ``indicator``.

        Returns one :class:`Verdict` per consulted provider. Never raises — a
        provider that errors yields a Verdict with ``ok=False`` and a scrubbed
        message so the analyst still sees the others.
        """
        indicator = (indicator or "").strip()
        if not indicator:
            return []
        kind = ioc_type or classify_indicator(indicator)
        verdicts: list[Verdict] = []

        if self._key(SETTING_VT):
            verdicts.append(self._virustotal(indicator, kind))
        if kind == "ip" and self._key(SETTING_ABUSEIPDB):
            verdicts.append(self._abuseipdb(indicator))
        if kind in ("ip", "domain", "hash", "url") and self._key(SETTING_OTX):
            verdicts.append(self._otx(indicator, kind))
        return verdicts

    # -- providers --
    def _get(self, url, headers):
        return retry_request(lambda: self.session.get(url, headers=headers, timeout=HTTP_TIMEOUT))

    def _virustotal(self, indicator, kind) -> Verdict:
        key = self._key(SETTING_VT)
        path = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}.get(kind)
        if not path:
            return Verdict("VirusTotal", indicator, ok=False,
                           error=f"VirusTotal has no lookup for '{kind}' indicators.")
        # VT keys URLs by their base64 id, but the search endpoint accepts the
        # raw value; use the object endpoint for the simple types.
        ident = indicator
        try:
            resp = self._get(f"https://www.virustotal.com/api/v3/{path}/{ident}",
                             {"x-apikey": key})
            if resp.status_code == 404:
                v = Verdict("VirusTotal", indicator)
                v.malicious = False
                v.detail = "Unknown to VirusTotal (no record)."
                v.link = f"https://www.virustotal.com/gui/search/{indicator}"
                return v
            if resp.status_code == 401:
                return Verdict("VirusTotal", indicator, ok=False, error="Invalid VirusTotal API key.")
            resp.raise_for_status()
            return _parse_virustotal(indicator, resp.json())
        except (RetryError, requests.RequestException, ValueError) as exc:
            return Verdict("VirusTotal", indicator, ok=False, error=_scrub(exc, key))

    def _abuseipdb(self, indicator) -> Verdict:
        key = self._key(SETTING_ABUSEIPDB)
        try:
            resp = self._get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={indicator}&maxAgeInDays=90",
                {"Key": key, "Accept": "application/json"})
            if resp.status_code == 401:
                return Verdict("AbuseIPDB", indicator, ok=False, error="Invalid AbuseIPDB API key.")
            resp.raise_for_status()
            return _parse_abuseipdb(indicator, resp.json())
        except (RetryError, requests.RequestException, ValueError) as exc:
            return Verdict("AbuseIPDB", indicator, ok=False, error=_scrub(exc, key))

    def _otx(self, indicator, kind) -> Verdict:
        key = self._key(SETTING_OTX)
        section = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}.get(kind, "domain")
        try:
            resp = self._get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
                {"X-OTX-API-KEY": key})
            if resp.status_code == 403:
                return Verdict("AlienVault OTX", indicator, ok=False, error="Invalid OTX API key.")
            resp.raise_for_status()
            return _parse_otx(indicator, resp.json())
        except (RetryError, requests.RequestException, ValueError) as exc:
            return Verdict("AlienVault OTX", indicator, ok=False, error=_scrub(exc, key))
