"""Security Orchestrator - manages all security detectors."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.security.detectors import (
    BeaconDetectionDetector,
    BruteForceDetector,
    ExfiltrationDetector,
    PrivilegeEscalationDetector,
    SQLInjectionDetector,
)
from src.security.schemas import SecurityAlert, SecurityDetectorInterface


class SecurityOrchestrator:
    """Orchestrates all security detectors and manages their lifecycle."""

    def __init__(self):
        """Initialize all security detectors."""
        self.detectors: List[SecurityDetectorInterface] = [
            BruteForceDetector(window_minutes=5, threshold_attempts=10),
            SQLInjectionDetector(sensitivity="medium"),
            PrivilegeEscalationDetector(),
            ExfiltrationDetector(bytes_threshold_mb=10, rate_threshold_mbps=5.0),
            BeaconDetectionDetector(min_beacon_interval=30, max_jitter_percentage=20),
        ]

        self.total_alerts = 0

    def analyze_log(self, log_line: str, context: Optional[Dict] = None) -> List[SecurityAlert]:
        """
        Analyze a log line with all detectors.

        Args:
            log_line: Raw log line
            context: Optional context dict

        Returns:
            List of SecurityAlerts raised (0 or more)
        """
        alerts = []

        for detector in self.detectors:
            try:
                result = detector.detect(log_line, context)
                if result:
                    alerts.append(result)
                    self.total_alerts += 1
            except Exception as e:
                # Log detector errors but don't crash
                print(f"Error in {detector.__class__.__name__}: {e}")

        return alerts

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics from all detectors."""
        metrics = {"total_alerts_raised": self.total_alerts}

        for detector in self.detectors:
            detector_name = detector.__class__.__name__
            metrics[detector_name] = detector.get_metrics()

        return metrics

    def update_detector_thresholds(
        self, detector_name: str, thresholds: Dict[str, float]
    ) -> bool:
        """Update thresholds for a specific detector."""
        for detector in self.detectors:
            if detector.__class__.__name__ == detector_name:
                detector.update_thresholds(thresholds)
                return True
        return False

    def list_detectors(self) -> List[str]:
        """List all loaded detectors."""
        return [d.__class__.__name__ for d in self.detectors]
