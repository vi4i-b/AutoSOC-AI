"""Anti-phishing analysis.

The engine combines several independent signal sources — URL structure, TLS
certificate, page content, and spelling/grammar — into a single weighted
score and verdict. Every signal is a :class:`~autosoc.phishing.signals.Signal`
with a category, weight, and human-readable explanation, so the UI can show
*why* a verdict was reached.

Network access is optional and always SSRF-guarded: URL-only heuristics work
offline, and page/TLS checks degrade gracefully when the site is unreachable.
"""

from autosoc.phishing.analyzer import PhishingAnalyzer, PhishingReport
from autosoc.phishing.signals import Signal

__all__ = ["PhishingAnalyzer", "PhishingReport", "Signal"]
