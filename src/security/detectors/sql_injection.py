"""SQL Injection Attack Detector."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from src.security.schemas import SecurityAlert, SecurityDetectorInterface


class SQLInjectionDetector(SecurityDetectorInterface):
    """Detects SQL injection patterns in web requests and logs."""

    # Common SQL injection signatures
    SQLI_PATTERNS = [
        r"(\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)",  # OR 1=1
        r"(\bUNION\s+SELECT)",  # UNION SELECT
        r"(;\s*DROP\s+TABLE)",  # DROP TABLE
        r"(;\s*DELETE\s+FROM)",  # DELETE FROM
        r"(\'?\s+--\s|\'?\s+#)",  # Comment syntax
        r"(EXEC\s*\(|EXECUTE\s*\()",  # Dynamic execution
        r"(xp_cmdshell|xp_regread)",  # SQL Server extended procedures
        r"(INTO\s+OUTFILE|INTO\s+DUMPFILE)",  # Data exfiltration
        r"(\bCASTING|\bCONCAT\s*\()",  # MySQL functions
        r"(sleep\s*\(\s*\d+|BENCHMARK\s*\()",  # Time-based SQLi
        r"(base64|decode|hex|unhex).*\(",  # Encoding bypass
        r"(/\*.*?\*/|--\s|#\s)",  # Comment obfuscation
        r"(\|\||&&|!)",  # Logical operators in strange places
        r"(\bAND\b.*\bWHERE\b|\bOR\b.*\bWHERE\b)",  # Suspicious conditions
        r"(updatexml|extractvalue|xmltype)",  # XML-based SQLi
    ]

    def __init__(self, sensitivity: str = "medium"):
        """
        Initialize SQL injection detector.

        Args:
            sensitivity: "low", "medium", or "high" - affects pattern matching
        """
        self.sensitivity = sensitivity
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.SQLI_PATTERNS]

        # Metrics
        self.total_processed = 0
        self.alerts_raised = 0

    def detect(self, log_line: str, context: Optional[Dict] = None) -> Optional[SecurityAlert]:
        """Detect SQL injection attempts."""
        self.total_processed += 1

        # Check each pattern
        matched_pattern = None
        for pattern in self.patterns:
            match = pattern.search(log_line)
            if match:
                matched_pattern = match.group(0)[:100]  # Truncate long matches
                break

        if not matched_pattern:
            return None

        # Extract location information if available
        location = "Unknown"
        if "GET" in log_line:
            location = "URL parameter"
        elif "POST" in log_line:
            location = "POST body"

        # Extract source IP if present
        source_ip = None
        ip_match = re.search(r"(?:from|from_ip|source|client)\s*=?\s*(\d+\.\d+\.\d+\.\d+)", log_line)
        if ip_match:
            source_ip = ip_match.group(1)

        self.alerts_raised += 1

        return SecurityAlert(
            timestamp=datetime.now(UTC),
            severity="CRITICAL",
            attack_type="SQL_INJECTION",
            description=f"Detected SQL injection attempt in {location}",
            source_ip=source_ip,
            mitre_technique="T1190 - Exploit Public-Facing Application",
            recommended_action="Block request and add to WAF ruleset",
            confidence=0.99,
            raw_log=log_line,
            detector_name="SQLInjectionDetector",
            metadata={
                "matched_pattern": matched_pattern,
                "location": location,
                "payload_length": len(log_line),
            },
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Return detector metrics."""
        return {
            "total_processed": self.total_processed,
            "alerts_raised": self.alerts_raised,
        }

    def update_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Update detector thresholds dynamically."""
        if "sensitivity" in thresholds:
            self.sensitivity = str(thresholds.get("sensitivity", "medium"))
