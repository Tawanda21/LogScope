from __future__ import annotations

from datetime import UTC, datetime
from typing import Iterable

from src.api.schemas import DetectionResult
from src.core.drift import DriftDetector
from src.core.frequency import FrequencyDetector
from src.core.parameter import ParameterDetector
from src.core.sequence import SequenceDetector
from src.parsing.log_parser import LogParser


class LogAnomalyDetector:
    def __init__(self) -> None:
        self.parser = LogParser()
        self.frequency = FrequencyDetector()
        self.parameter = ParameterDetector()
        self.sequence = SequenceDetector()
        self.drift = DriftDetector()

    def score(self, log_line: str, timestamp: datetime | None = None) -> DetectionResult:
        template, parameters = self.parser.parse(log_line)

        frequency_score = self.frequency.score(template)
        parameter_score = self.parameter.score(parameters)
        sequence_score = self.sequence.score(template)
        drift_score = 1.0 if self.drift.update(frequency_score) else 0.0

        anomaly_score = self.combine_scores(frequency_score, parameter_score, sequence_score, drift_score)
        result = DetectionResult(
            timestamp=timestamp or datetime.now(UTC),
            template=template,
            parameters=list(parameters),
            frequency_score=frequency_score,
            parameter_score=parameter_score,
            sequence_score=sequence_score,
            drift_score=drift_score,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= 0.65,
            explanation=self.explain(template, parameters, anomaly_score),
        )

        self.frequency.update(template)
        self.parameter.update(parameters)
        self.sequence.update(template)
        return result

    @staticmethod
    def combine_scores(*scores: float) -> float:
        if not scores:
            return 0.0
        weighted = 0.35 * scores[0] + 0.25 * scores[1] + 0.25 * scores[2] + 0.15 * scores[3]
        return max(0.0, min(1.0, weighted))

    @staticmethod
    def explain(template: str, parameters: Iterable[str], anomaly_score: float) -> str:
        if anomaly_score < 0.65:
            return "Pattern is consistent with prior observations."
        parameter_text = ", ".join(parameters) if parameters else "no parameters"
        return f"Unusual log pattern detected for template '{template}' with {parameter_text}."
