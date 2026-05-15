"""Data Exfiltration Attack Detector."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from src.security.schemas import SecurityAlert, SecurityDetectorInterface


class ExfiltrationDetector(SecurityDetectorInterface):
    """Detects unusual data transfers and exfiltration attempts."""

    # Patterns for exfiltration indicators
    EXFIL_PATTERNS = [
        r"uploaded\s+(\d+\s*(?:MB|GB|KB))",  # File upload
        r"transferred\s+(\d+\s*(?:MB|GB))",  # Data transfer
        r"FTP|SFTP.*\d+\s*(?:MB|GB)",  # FTP/SFTP large transfer
        r"outbound.*traffic.*spike",  # Traffic spike
        r"DNS\s+query:.*\.",  # Suspicious DNS
        r"(S3|bucket|cloud).*upload",  # Cloud upload
    ]

    def __init__(self, bytes_threshold_mb: int = 10, rate_threshold_mbps: float = 5.0):
        """
        Initialize exfiltration detector.

        Args:
            bytes_threshold_mb: Alert if transfer > this many MB
            rate_threshold_mbps: Alert if rate > this many Mbps
        """
        self.bytes_threshold_mb = bytes_threshold_mb
        self.rate_threshold_mbps = rate_threshold_mbps
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.EXFIL_PATTERNS]
        self.total_processed = 0
        self.alerts_raised = 0

    def detect(self, log_line: str, context: Optional[Dict] = None) -> Optional[SecurityAlert]:
        """Detect data exfiltration."""
        self.total_processed += 1

        matched_pattern = None
        for pattern in self.patterns:
            match = pattern.search(log_line)
            if match:
                matched_pattern = match.group(0)[:100]
                break

        if not matched_pattern:
            return None

        # Extract user if present
        user = "unknown"
        user_match = re.search(r"user\s+(\S+)|USER\s+(\S+)", log_line)
        if user_match:
            user = user_match.group(1) or user_match.group(2)

        # Extract destination IP if present
        dest_ip = None
        ip_match = re.search(
            r"(?:to|destination|dest)\s+(\d+\.\d+\.\d+\.\d+)",
            log_line,
            re.IGNORECASE,
        )
        if ip_match:
            dest_ip = ip_match.group(1)

        # Extract transfer size
        bytes_transferred = 0
        size_match = re.search(r"(\d+)\s*(?:MB|GB|KB)", log_line)
        if size_match:
            value = int(size_match.group(1))
            if "GB" in log_line:
                bytes_transferred = value * 1024
            elif "MB" in log_line:
                bytes_transferred = value
            else:
                bytes_transferred = value // 1024

        if bytes_transferred > self.bytes_threshold_mb:
            self.alerts_raised += 1

            return SecurityAlert(
                timestamp=datetime.now(UTC),
                severity="CRITICAL",
                attack_type="DATA_EXFILTRATION",
                description=f"Detected suspicious data transfer of {bytes_transferred}MB by user {user}",
                target_user=user,
                source_ip=dest_ip,
                mitre_technique="TA0010 - Exfiltration",
                recommended_action=f"Isolate user session for {user} and rotate credentials",
                confidence=0.92,
                raw_log=log_line,
                detector_name="ExfiltrationDetector",
                metadata={
                    "bytes_transferred": bytes_transferred,
                    "destination_ip": dest_ip,
                    "threshold_mb": self.bytes_threshold_mb,
                },
            )

        return None

    def get_metrics(self) -> Dict[str, Any]:
        """Return detector metrics."""
        return {
            "total_processed": self.total_processed,
            "alerts_raised": self.alerts_raised,
        }

    def update_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Update detector thresholds."""
        if "bytes_threshold_mb" in thresholds:
            self.bytes_threshold_mb = int(thresholds["bytes_threshold_mb"])
        if "rate_threshold_mbps" in thresholds:
            self.rate_threshold_mbps = float(thresholds["rate_threshold_mbps"])
