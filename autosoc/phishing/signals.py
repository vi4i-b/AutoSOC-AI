"""Signal primitives shared by the anti-phishing detectors."""

from dataclasses import dataclass, field

# Verdict bands keyed by score (0 = safe, 100 = almost certainly phishing).
VERDICT_BANDS = [
    (80, "Dangerous", "High confidence this is a phishing or malicious page."),
    (55, "Suspicious", "Multiple phishing indicators found. Treat with caution."),
    (30, "Questionable", "Some risk signals present. Verify before trusting."),
    (0, "Likely Safe", "No strong phishing indicators found."),
]

# Category weights let one strong category (e.g. a credential form on a
# look-alike domain) dominate without being drowned out by minor noise.
SEVERITY_LOW = 6
SEVERITY_MEDIUM = 14
SEVERITY_HIGH = 24
SEVERITY_CRITICAL = 34


@dataclass
class Signal:
    """One observation contributing to the phishing score."""

    category: str          # "URL", "TLS", "Content", "Spelling", "Reputation", "AI"
    title: str
    detail: str
    weight: int            # points added toward the phishing score
    hit: bool              # True = risky observation; False = reassuring/informational

    @property
    def score(self) -> int:
        return self.weight if self.hit else 0


@dataclass
class SignalSet:
    """Accumulates signals and exposes convenience queries."""

    signals: list = field(default_factory=list)

    def add(self, category, title, detail, weight, hit=True):
        self.signals.append(Signal(category, title, detail, weight, hit))

    def extend(self, other):
        self.signals.extend(other.signals if isinstance(other, SignalSet) else other)

    def hits(self):
        return [signal for signal in self.signals if signal.hit]

    def total_score(self) -> int:
        return sum(signal.score for signal in self.signals)


def clamp_score(value) -> int:
    return max(0, min(100, int(round(value))))


def verdict_for_score(score):
    """Return (label, description) for a 0-100 score."""
    for threshold, label, description in VERDICT_BANDS:
        if score >= threshold:
            return label, description
    return VERDICT_BANDS[-1][1], VERDICT_BANDS[-1][2]
