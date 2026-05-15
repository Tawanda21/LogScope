"""Security alert schemas and types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, Optional


@dataclass
class SecurityAlert:
    """Standard alert format for all security detectors."""

    timestamp: datetime
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    attack_type: str  # SSH_BRUTE_FORCE, SQL_INJECTION, etc.
    description: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    mitre_technique: Optional[str] = None
    recommended_action: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    raw_log: str = ""
    detector_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "attack_type": self.attack_type,
            "description": self.description,
            "source_ip": self.source_ip,
            "target_user": self.target_user,
            "mitre_technique": self.mitre_technique,
            "recommended_action": self.recommended_action,
            "confidence": self.confidence,
            "detector_name": self.detector_name,
            "metadata": self.metadata,
        }


class SecurityDetectorInterface:
    """Base interface all security detectors must implement."""

    def detect(self, log_line: str, context: Optional[Dict] = None) -> Optional[SecurityAlert]:
        """
        Analyze a single log line for security threats.

        Args:
            log_line: Raw log line as string
            context: Optional dict with session/user info

        Returns:
            SecurityAlert if threat detected, None otherwise
        """
        raise NotImplementedError

    def get_metrics(self) -> Dict[str, Any]:
        """
        Return detector metrics.

        Returns:
            Dict with keys: total_processed, alerts_raised
        """
        raise NotImplementedError

    def update_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Allow dynamic threshold tuning without restart."""
        raise NotImplementedError
