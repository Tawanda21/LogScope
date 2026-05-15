"""Privilege Escalation Attack Detector."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from src.security.schemas import SecurityAlert, SecurityDetectorInterface


class PrivilegeEscalationDetector(SecurityDetectorInterface):
    """Detects privilege escalation attempts (sudo abuse, setuid, etc)."""

    # Patterns for privilege escalation
    PRIV_ESC_PATTERNS = [
        r"sudo:.*COMMAND=(/bin/(bash|sh|zsh))",  # Sudo shell access
        r"sudo:.*USER=root",  # Sudo to root
        r"(chmod|chown).*4755.*(/bin/|/sbin/)",  # Suspicious setuid
        r"LD_PRELOAD.*sudo",  # LD_PRELOAD hijack
        r"sudo:.*\(root\)\s*NOPASSWD",  # NOPASSWD sudo
        r"setuid.*(/bin/|/sbin/)",  # Setuid binary execution
        r"attempted to access.*shadow",  # Shadow file access
        r"denied.*sudo",  # Sudo denial (permission test)
        r"(su\s+root|su\s+-)",  # su to root
    ]

    def __init__(self):
        """Initialize privilege escalation detector."""
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.PRIV_ESC_PATTERNS]
        self.total_processed = 0
        self.alerts_raised = 0

    def detect(self, log_line: str, context: Optional[Dict] = None) -> Optional[SecurityAlert]:
        """Detect privilege escalation attempts."""
        self.total_processed += 1

        matched_pattern = None
        for pattern in self.patterns:
            match = pattern.search(log_line)
            if match:
                matched_pattern = match.group(0)[:100]
                break

        if not matched_pattern:
            return None

        # Extract username
        user = "unknown"
        user_match = re.search(r"(?:user|sudo|su)\s+(?:=\s*)?(\S+)", log_line)
        if user_match:
            user = user_match.group(1)

        self.alerts_raised += 1

        return SecurityAlert(
            timestamp=datetime.now(UTC),
            severity="CRITICAL",
            attack_type="PRIVILEGE_ESCALATION",
            description=f"Detected privilege escalation attempt by user {user}",
            target_user=user,
            mitre_technique="TA0004 - Privilege Escalation",
            recommended_action=f"Revoke sudo rights for user {user} and investigate",
            confidence=0.88,
            raw_log=log_line,
            detector_name="PrivilegeEscalationDetector",
            metadata={
                "matched_pattern": matched_pattern,
                "target_user": user,
            },
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Return detector metrics."""
        return {
            "total_processed": self.total_processed,
            "alerts_raised": self.alerts_raised,
        }

    def update_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Update detector thresholds."""
        pass
