"""Compatibility wrapper for simple public API used in the README.

Provides `LogMonitor` which wraps the internal LogAnomalyDetector and exposes
`process(line)` -> (is_anomaly: bool, explanation: str) for quick experiments.
"""
from __future__ import annotations

from typing import Tuple

from src.core.detector import LogAnomalyDetector


class LogMonitor:
    def __init__(self) -> None:
        self._detector = LogAnomalyDetector()

    def process(self, log_line: str) -> Tuple[bool, str]:
        """Process a single log line and return (is_anomaly, explanation)."""
        result = self._detector.score(log_line)
        return bool(result.is_anomaly), result.explanation

__all__ = ["LogMonitor"]
