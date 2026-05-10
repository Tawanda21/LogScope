from __future__ import annotations

from collections import defaultdict


class SequenceDetector:
    def __init__(self) -> None:
        self.transitions = defaultdict(lambda: defaultdict(int))
        self.previous_template: str | None = None

    def update(self, template: str) -> None:
        if self.previous_template is not None:
            self.transitions[self.previous_template][template] += 1
        self.previous_template = template

    def score(self, template: str) -> float:
        if self.previous_template is None:
            return 0.0

        branch = self.transitions[self.previous_template]
        if not branch:
            return 0.5

        total = sum(branch.values())
        probability = branch.get(template, 0) / total
        return float(1.0 - probability)
