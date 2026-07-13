"""Page-content heuristics.

Given a fetched page (see :mod:`autosoc.phishing.fetcher`) these checks look
for the behavioral fingerprints of a phishing page: credential-harvesting
forms that post off-site, urgency/scare language, brand impersonation in the
visible text, obfuscation, and framing of another site.
"""

import re
from urllib.parse import urlparse

from autosoc.phishing.signals import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SignalSet,
)
from autosoc.phishing.spelling import analyze_spelling
from autosoc.phishing.url_features import IMPERSONATED_BRANDS

# Urgency / social-engineering phrases across the app's three languages.
URGENCY_PHRASES = [
    "verify your account", "suspended", "unusual activity", "confirm your identity",
    "update your payment", "act now", "within 24 hours", "your account will be",
    "click here immediately", "limited time", "unauthorized login", "security alert",
    "account locked", "re-enter your password", "validate your account",
    "срочно", "подтвердите", "ваш аккаунт", "заблокирован", "немедленно",
    "подтвердить личность", "необычная активность", "в течение 24",
    "təcili", "hesabınız", "təsdiqləyin", "bloklan", "dərhal",
]

_PASSWORD_FIELD_RE = re.compile(r"type\s*=\s*[\"']?password", re.IGNORECASE)


def _registered_domain(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def analyze_content(fetch_result, expected_host: str = "") -> SignalSet:
    signals = SignalSet()
    if not fetch_result or not fetch_result.ok:
        return signals

    page_host = urlparse(fetch_result.final_url or fetch_result.url).hostname or expected_host
    page_domain = _registered_domain(page_host)
    text = fetch_result.text or ""
    lowered_text = text.lower()

    # Redirect chain crossing domains
    if fetch_result.redirect_chain:
        start_host = urlparse(fetch_result.url).hostname or ""
        if _registered_domain(start_host) != page_domain:
            signals.add("Content", "Cross-domain redirect",
                        f"The URL redirected from {start_host} to {page_host} — a different domain.",
                        SEVERITY_MEDIUM, hit=True)

    # Credential forms
    if fetch_result.password_inputs:
        off_site_forms = []
        for form in fetch_result.forms:
            if "password" not in form.get("inputs", []):
                continue
            action = form.get("action", "")
            action_host = urlparse(action).hostname if action else None
            if action_host and _registered_domain(action_host) != page_domain:
                off_site_forms.append(action_host)

        if off_site_forms:
            signals.add("Content", "Credential form posts off-site",
                        "A password form submits to a different domain: " + ", ".join(sorted(set(off_site_forms))) + ".",
                        SEVERITY_CRITICAL, hit=True)
        else:
            signals.add("Content", "Password form present",
                        "The page collects a password. Legitimate for login pages, but the top target of phishing.",
                        SEVERITY_MEDIUM, hit=True)

    # Insecure form on an HTTPS-less page
    if fetch_result.password_inputs and urlparse(fetch_result.final_url or fetch_result.url).scheme != "https":
        signals.add("Content", "Password over HTTP",
                    "A password field is served over an unencrypted connection.",
                    SEVERITY_HIGH, hit=True)

    # Urgency language
    urgency_hits = sorted({phrase for phrase in URGENCY_PHRASES if phrase in lowered_text})
    if urgency_hits:
        preview = ", ".join(f'"{phrase}"' for phrase in urgency_hits[:4])
        signals.add("Content", "Urgency / scare language",
                    f"The page uses pressure phrases typical of phishing: {preview}.",
                    SEVERITY_MEDIUM if len(urgency_hits) < 3 else SEVERITY_HIGH, hit=True)

    # Brand impersonation in visible text while off the brand's domain
    for brand in IMPERSONATED_BRANDS:
        if brand in lowered_text and brand not in (page_domain or ""):
            # Require the brand to be prominent (title or repeated) to reduce noise.
            if brand in (fetch_result.title or "").lower() or lowered_text.count(brand) >= 2:
                signals.add("Content", "Brand impersonation in content",
                            f"The page presents itself as '{brand}' but is hosted on {page_host}.",
                            SEVERITY_HIGH, hit=True)
                break

    # Obfuscation / heavy inline scripting
    if fetch_result.scripts_inline >= 5:
        signals.add("Content", "Heavy inline scripting",
                    f"The page has {fetch_result.scripts_inline} inline scripts, sometimes used to obfuscate phishing logic.",
                    SEVERITY_LOW, hit=True)
    if fetch_result.iframes:
        signals.add("Content", "Iframe embedding",
                    f"The page embeds {fetch_result.iframes} iframe(s); phishing pages frame real sites to look genuine.",
                    SEVERITY_LOW, hit=True)
    if fetch_result.hidden_inputs >= 5:
        signals.add("Content", "Many hidden inputs",
                    f"The page has {fetch_result.hidden_inputs} hidden form fields.",
                    SEVERITY_LOW, hit=True)

    # Empty / thin page (parked or cloaked)
    if fetch_result.status_code == 200 and len(text) < 40 and not fetch_result.forms:
        signals.add("Content", "Thin or cloaked page",
                    "The page has almost no visible content, which can indicate cloaking or a parked domain.",
                    SEVERITY_LOW, hit=True)

    # Spelling
    spelling = analyze_spelling(text)
    if spelling["homographs"]:
        sample = ", ".join(spelling["homographs"][:5])
        signals.add("Spelling", "Homograph text",
                    f"Visible text mixes look-alike alphabets in: {sample}.",
                    SEVERITY_HIGH, hit=True)
    if spelling["misspellings"]:
        sample = ", ".join(f"{bad}→{good}" for bad, good in spelling["misspellings"][:5])
        weight = SEVERITY_MEDIUM if len(spelling["misspellings"]) >= 3 else SEVERITY_LOW
        signals.add("Spelling", "Spelling errors",
                    f"Found {len(spelling['misspellings'])} likely misspelling(s): {sample}.",
                    weight, hit=True)

    signals._spelling = spelling  # attach for the UI/report
    return signals
