"""Tests for security detectors."""

import pytest

from src.security.detectors import (
    BeaconDetectionDetector,
    BruteForceDetector,
    ExfiltrationDetector,
    PrivilegeEscalationDetector,
    SQLInjectionDetector,
)
from src.security.orchestrator import SecurityOrchestrator


class TestBruteForceDetector:
    """Test SSH brute force detection."""

    def test_detects_failed_ssh_login(self):
        """Test detection of single failed SSH login."""
        detector = BruteForceDetector(threshold_attempts=2)
        log1 = "Failed password for root from 203.0.113.45 port 22 ssh2"
        log2 = "Failed password for root from 203.0.113.45 port 22 ssh2"

        result1 = detector.detect(log1)
        assert result1 is None  # First attempt below threshold

        result2 = detector.detect(log2)
        assert result2 is not None  # Second attempt hits threshold
        assert result2.severity == "HIGH"
        assert result2.attack_type == "SSH_BRUTE_FORCE"
        assert result2.source_ip == "203.0.113.45"

    def test_metrics(self):
        """Test detector metrics."""
        detector = BruteForceDetector()
        detector.detect("Some log")
        metrics = detector.get_metrics()

        assert metrics["total_processed"] == 1
        assert "alerts_raised" in metrics


class TestSQLInjectionDetector:
    """Test SQL injection detection."""

    def test_detects_or_equals_sqli(self):
        """Test detection of OR 1=1 pattern."""
        detector = SQLInjectionDetector()
        log = "GET /user?id=1' OR '1'='1 HTTP/1.1"

        result = detector.detect(log)
        assert result is not None
        assert result.severity == "CRITICAL"
        assert result.attack_type == "SQL_INJECTION"

    def test_detects_union_select(self):
        """Test detection of UNION SELECT."""
        detector = SQLInjectionDetector()
        log = "POST /search data='UNION SELECT * FROM users'"

        result = detector.detect(log)
        assert result is not None
        assert result.attack_type == "SQL_INJECTION"

    def test_normal_log_no_alert(self):
        """Test normal log does not trigger alert."""
        detector = SQLInjectionDetector()
        log = "GET /api/users HTTP/1.1"

        result = detector.detect(log)
        assert result is None


class TestPrivilegeEscalationDetector:
    """Test privilege escalation detection."""

    def test_detects_sudo_shell(self):
        """Test detection of sudo shell access."""
        detector = PrivilegeEscalationDetector()
        log = "sudo: john : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"

        result = detector.detect(log)
        assert result is not None
        assert result.severity == "CRITICAL"
        assert result.attack_type == "PRIVILEGE_ESCALATION"


class TestExfiltrationDetector:
    """Test data exfiltration detection."""

    def test_detects_large_upload(self):
        """Test detection of large file upload."""
        detector = ExfiltrationDetector(bytes_threshold_mb=5)
        log = "USER bob uploaded 10MB to 203.0.113.200 via FTP"

        result = detector.detect(log)
        assert result is not None
        assert result.severity == "CRITICAL"
        assert result.attack_type == "DATA_EXFILTRATION"


class TestBeaconDetector:
    """Test C2 beacon detection."""

    def test_detects_suspicious_domain(self):
        """Test detection of suspicious Windows domain."""
        detector = BeaconDetectionDetector()
        log = "DNS query: windows-defender-sys.com from 10.0.0.45"

        result = detector.detect(log)
        assert result is not None
        assert result.attack_type == "C2_BEACONING"

    def test_detects_periodic_connection(self):
        """Test detection of periodic beaconing."""
        detector = BeaconDetectionDetector(min_beacon_interval=30)
        log = "10.0.0.45:54321 -> 185.130.5.253:443 [every 60 seconds]"

        result = detector.detect(log)
        assert result is not None
        assert result.attack_type == "C2_BEACONING"


class TestSecurityOrchestrator:
    """Test security orchestrator."""

    def test_orchestrator_initialization(self):
        """Test orchestrator loads all detectors."""
        orchestrator = SecurityOrchestrator()

        detectors = orchestrator.list_detectors()
        assert "BruteForceDetector" in detectors
        assert "SQLInjectionDetector" in detectors
        assert "PrivilegeEscalationDetector" in detectors

    def test_orchestrator_analyzes_log(self):
        """Test orchestrator analyzes logs with all detectors."""
        orchestrator = SecurityOrchestrator()
        log = "GET /user?id=1' OR '1'='1 HTTP/1.1"

        alerts = orchestrator.analyze_log(log)
        assert len(alerts) > 0
        assert alerts[0].attack_type == "SQL_INJECTION"

    def test_orchestrator_metrics(self):
        """Test orchestrator returns metrics."""
        orchestrator = SecurityOrchestrator()
        orchestrator.analyze_log("GET /user?id=1' OR '1'='1 HTTP/1.1")

        metrics = orchestrator.get_all_metrics()
        assert "total_alerts_raised" in metrics
        assert metrics["total_alerts_raised"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
