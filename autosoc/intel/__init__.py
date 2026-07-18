"""Threat-intelligence enrichment for indicators of compromise.

Queries the reputation services SOC analysts actually reach for — VirusTotal,
AbuseIPDB and AlienVault OTX — and normalizes their answers into a single
verdict shape the UI can render. Providers are optional: each is used only if
its API key is configured, so the module is inert (and free) until an analyst
opts in.
"""

from autosoc.intel.enrichment import (
    ThreatIntelEnricher,
    Verdict,
    classify_indicator,
)

__all__ = ["ThreatIntelEnricher", "Verdict", "classify_indicator"]
