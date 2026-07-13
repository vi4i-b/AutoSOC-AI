"""Anti-phishing orchestrator.

:class:`PhishingAnalyzer` runs the individual detectors and combines their
signals into a single :class:`PhishingReport`. It works in two tiers:

  * ``quick_scan`` — URL heuristics only, fully offline and instant.
  * ``full_scan`` — adds TLS inspection, page fetch, content and spelling
    analysis, and (optionally) an AI verdict from a configured model.

The final score is capped so no single category can exceed the maximum, and
the AI verdict nudges the score rather than overriding the deterministic
evidence.
"""

from dataclasses import dataclass, field

from autosoc.logging_setup import get_logger
from autosoc.phishing.content_features import analyze_content
from autosoc.phishing.fetcher import fetch_page
from autosoc.phishing.signals import SignalSet, clamp_score, verdict_for_score
from autosoc.phishing.tls_check import analyze_tls
from autosoc.phishing.url_features import analyze_url, normalize_url, parsed_host

log = get_logger("phishing.analyzer")


@dataclass
class PhishingReport:
    url: str
    host: str = ""
    score: int = 0
    verdict: str = "Unknown"
    verdict_detail: str = ""
    signals: list = field(default_factory=list)
    spelling: dict = field(default_factory=dict)
    fetch_ok: bool = False
    fetch_error: str = ""
    page_title: str = ""
    final_url: str = ""
    ai_summary: str = ""
    ai_used: bool = False

    def hits(self):
        return [s for s in self.signals if s.hit]

    def by_category(self):
        grouped = {}
        for signal in self.signals:
            grouped.setdefault(signal.category, []).append(signal)
        return grouped


class PhishingAnalyzer:
    # No single category may contribute more than this to keep scores balanced.
    CATEGORY_CAP = 55

    def __init__(self, ai_client=None):
        self.ai_client = ai_client

    def quick_scan(self, raw_url: str) -> PhishingReport:
        signals = analyze_url(raw_url)
        return self._finalize(raw_url, signals)

    def full_scan(self, raw_url: str, use_ai: bool = True) -> PhishingReport:
        signals = SignalSet()
        signals.extend(analyze_url(raw_url))

        try:
            signals.extend(analyze_tls(raw_url))
        except Exception as exc:
            log.debug("TLS analysis error: %s", exc)

        fetch_result = fetch_page(raw_url)
        content_signals = analyze_content(fetch_result, expected_host=parsed_host(raw_url))
        signals.extend(content_signals)
        spelling = getattr(content_signals, "_spelling", {}) or {}

        report = self._finalize(
            raw_url,
            signals,
            fetch_result=fetch_result,
            spelling=spelling,
        )

        if use_ai and self.ai_client is not None and getattr(self.ai_client, "enabled", False):
            self._apply_ai(report, fetch_result)

        return report

    def _apply_ai(self, report, fetch_result):
        text_excerpt = (fetch_result.text or "")[:4000] if fetch_result and fetch_result.ok else ""
        try:
            ai_result = self.ai_client.analyze_phishing(
                url=report.url,
                page_title=report.page_title,
                page_text=text_excerpt,
                heuristic_signals=[(s.category, s.title, s.detail) for s in report.hits()],
                heuristic_score=report.score,
            )
        except Exception as exc:
            log.debug("AI phishing analysis error: %s", exc)
            return

        if not ai_result:
            return

        report.ai_used = True
        report.ai_summary = ai_result.get("summary", "").strip()
        ai_score = ai_result.get("score")
        if isinstance(ai_score, (int, float)):
            # Blend: deterministic evidence 60%, model judgment 40%.
            blended = round(report.score * 0.6 + float(ai_score) * 0.4)
            report.score = clamp_score(blended)
            report.verdict, report.verdict_detail = verdict_for_score(report.score)

    def _finalize(self, raw_url, signals, fetch_result=None, spelling=None):
        # Cap each category's contribution, then sum.
        per_category = {}
        for signal in signals.signals:
            if signal.hit:
                per_category[signal.category] = per_category.get(signal.category, 0) + signal.score
        capped_total = sum(min(total, self.CATEGORY_CAP) for total in per_category.values())
        score = clamp_score(capped_total)
        verdict, verdict_detail = verdict_for_score(score)

        report = PhishingReport(
            url=normalize_url(raw_url),
            host=parsed_host(raw_url),
            score=score,
            verdict=verdict,
            verdict_detail=verdict_detail,
            signals=list(signals.signals),
            spelling=spelling or {},
        )
        if fetch_result is not None:
            report.fetch_ok = fetch_result.ok
            report.fetch_error = fetch_result.error
            report.page_title = fetch_result.title
            report.final_url = fetch_result.final_url or fetch_result.url
        return report
