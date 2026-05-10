from __future__ import annotations

from collections import Counter, defaultdict
from math import exp


class FrequencyDetector:
    def __init__(self) -> None:
        self.template_counts = Counter()
        self.total_events = 0
        self.template_first_seen = defaultdict(int)

    def update(self, template: str) -> None:
        self.total_events += 1
        self.template_counts[template] += 1
        self.template_first_seen.setdefault(template, self.total_events)

    def score(self, template: str) -> float:
        count = self.template_counts.get(template, 0)
        if self.total_events == 0:
            return 0.0

        expected_rate = max(self.total_events / max(len(self.template_counts), 1), 1e-6)
        observed = count + 1
        rarity = exp(-observed / expected_rate)
        novelty = 1.0 if count == 0 else 0.0
        return min(1.0, 0.7 * rarity + 0.3 * novelty)
