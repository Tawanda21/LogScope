"""SSH Brute Force Attack Detector."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

from src.security.schemas import SecurityAlert, SecurityDetectorInterface


class BruteForceDetector(SecurityDetectorInterface):
    """Detects SSH/FTP brute force attacks via failed login patterns."""

    # Regex patterns for failed login attempts
    SSH_FAILED_PATTERNS = [
        r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)",
        r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
        r"pam_unix.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
    ]

    FTP_FAILED_PATTERNS = [
        r"530 Login incorrect from (\d+\.\d+\.\d+\.\d+)",
        r"User .+ (.*) failed\.",
    ]

    def __init__(self, window_minutes: int = 5, threshold_attempts: int = 10):
        """
        Initialize brute force detector.

        Args:
            window_minutes: Rolling time window for failed attempt tracking
            threshold_attempts: Number of attempts to trigger alert
        """
        self.window_minutes = window_minutes
        self.threshold_attempts = threshold_attempts

        # Track failed attempts: {source_ip: [(timestamp, username), ...]}
        self.failed_attempts: Dict[str, list[tuple[datetime, str]]] = defaultdict(list)

        # Metrics
        self.total_processed = 0
        self.alerts_raised = 0

    def detect(self, log_line: str, context: Optional[Dict] = None) -> Optional[SecurityAlert]:
        """Detect SSH/FTP brute force attacks."""
        self.total_processed += 1

        source_ip = None
        username = "unknown"

        # Try SSH patterns
        for pattern in self.SSH_FAILED_PATTERNS:
            match = re.search(pattern, log_line)
            if match:
                source_ip = match.group(1)
                # Extract username if present
                user_match = re.search(r"for (\S+) from", log_line)
                if user_match:
                    username = user_match.group(1)
                break

        # Try FTP patterns
        if not source_ip:
            for pattern in self.FTP_FAILED_PATTERNS:
                match = re.search(pattern, log_line)
                if match:
                    source_ip = match.group(1)
                    break

        if not source_ip:
            return None

        # Record attempt with timestamp
        now = datetime.now(UTC)
        self.failed_attempts[source_ip].append((now, username))

        # Clean old attempts outside the window
        cutoff_time = now - timedelta(minutes=self.window_minutes)
        self.failed_attempts[source_ip] = [
            (ts, user) for ts, user in self.failed_attempts[source_ip]
            if ts > cutoff_time
        ]

        # Check if threshold exceeded
        attempt_count = len(self.failed_attempts[source_ip])
        if attempt_count >= self.threshold_attempts:
            self.alerts_raised += 1

            return SecurityAlert(
                timestamp=now,
                severity="HIGH",
                attack_type="SSH_BRUTE_FORCE",
                description=f"Detected {attempt_count} failed SSH login attempts from {source_ip} in {self.window_minutes} minutes",
                source_ip=source_ip,
                target_user=username,
                mitre_technique="T1110.001 - Password Guessing",
                recommended_action=f"iptables -A INPUT -s {source_ip} -j DROP",
                confidence=0.95,
                raw_log=log_line,
                detector_name="BruteForceDetector",
                metadata={
                    "failed_attempts": attempt_count,
                    "time_window_minutes": self.window_minutes,
                    "target_users": list(set(user for _, user in self.failed_attempts[source_ip])),
                },
            )

        return None

    def get_metrics(self) -> Dict[str, Any]:
        """Return detector metrics."""
        return {
            "total_processed": self.total_processed,
            "alerts_raised": self.alerts_raised,
            "tracked_ips": len(self.failed_attempts),
        }

    def update_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Update detector thresholds dynamically."""
        if "threshold_attempts" in thresholds:
            self.threshold_attempts = int(thresholds["threshold_attempts"])
        if "window_minutes" in thresholds:
            self.window_minutes = int(thresholds["window_minutes"])
