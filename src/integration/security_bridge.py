"""Integration bridge between security and ML detection."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.api.schemas import DetectionResult
from src.core.detector import LogAnomalyDetector
from src.security.orchestrator import SecurityOrchestrator
from src.security.schemas import SecurityAlert


class UnifiedDetectionPipeline:
    """Combines ML and security detection for complete threat coverage."""

    def __init__(self):
        """Initialize ML and security detectors."""
        self.ml_detector = LogAnomalyDetector()
        self.security_orchestrator = SecurityOrchestrator()

    def analyze_log(
        self, log_line: str, context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze log with both ML and security detectors.

        Returns:
            Dict with:
                - ml_result: DetectionResult from ML engine
                - security_alerts: List of SecurityAlerts
                - combined_severity: Highest severity from all detectors
        """
        # ML detection
        ml_result = self.ml_detector.score(log_line)

        # Security detection
        security_alerts = self.security_orchestrator.analyze_log(log_line, context)

        # Determine combined severity
        combined_severity = "NORMAL"
        if ml_result.is_anomaly:
            combined_severity = "MEDIUM"

        for alert in security_alerts:
            if alert.severity == "CRITICAL":
                combined_severity = "CRITICAL"
                break
            elif alert.severity == "HIGH" and combined_severity != "CRITICAL":
                combined_severity = "HIGH"

        return {
            "log": log_line,
            "ml_result": ml_result.model_dump(),
            "security_alerts": [alert.to_dict() for alert in security_alerts],
            "combined_severity": combined_severity,
            "total_alerts": len(security_alerts),
            "anomaly_score": ml_result.anomaly_score,
        }

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get summary for dashboard display."""
        ml_metrics = {"detector": "ML Engine", "scores": "N/A"}
        security_metrics = self.security_orchestrator.get_all_metrics()

        return {
            "ml_metrics": ml_metrics,
            "security_metrics": security_metrics,
            "active_detectors": self.security_orchestrator.list_detectors(),
        }
