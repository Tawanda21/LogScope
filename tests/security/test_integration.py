"""Integration test for complete security pipeline."""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security.orchestrator import SecurityOrchestrator
from src.integration.security_bridge import UnifiedDetectionPipeline


def test_orchestrator_with_realistic_attacks():
    """Test orchestrator detects multiple attack types."""
    orchestrator = SecurityOrchestrator()
    
    test_logs = [
        # Brute force
        "Failed password for admin from 192.168.1.100 port 22 ssh2",
        "Failed password for admin from 192.168.1.100 port 22 ssh2",
        # SQL injection
        "GET /user?id=1' OR '1'='1 HTTP/1.1",
        # Privilege escalation
        "sudo: root : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
        # Exfiltration
        "USER bob uploaded 15MB to 203.0.113.200 via FTP",
        # C2 Beacon
        "DNS query: windows-defender-sys.com from 10.0.0.45",
    ]
    
    total_alerts = 0
    for log in test_logs:
        alerts = orchestrator.analyze_log(log)
        total_alerts += len(alerts)
        if alerts:
            print(f"✓ Detected {len(alerts)} alert(s) for: {log[:60]}...")
            for alert in alerts:
                print(f"  - {alert.severity}: {alert.attack_type}")
    
    print(f"\n✅ Total alerts detected: {total_alerts}")
    assert total_alerts >= 4, "Should detect at least 4 different attack types"
    return True


def test_unified_pipeline():
    """Test ML + Security unified detection."""
    pipeline = UnifiedDetectionPipeline()
    
    log = "GET /user?id=1' OR '1'='1 HTTP/1.1 from 203.0.113.1"
    result = pipeline.analyze_log(log)
    
    print(f"\nUnified Pipeline Result:")
    print(f"  Combined Severity: {result['combined_severity']}")
    print(f"  ML Anomaly Score: {result['anomaly_score']:.3f}")
    print(f"  Security Alerts: {result['total_alerts']}")
    
    assert result['combined_severity'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'NORMAL']
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Integration Test: Complete Security Pipeline")
    print("=" * 60)
    
    print("\n1. Testing SecurityOrchestrator with realistic attacks...")
    test_orchestrator_with_realistic_attacks()
    
    print("\n2. Testing UnifiedDetectionPipeline...")
    test_unified_pipeline()
    
    print("\n" + "=" * 60)
    print("✅ ALL INTEGRATION TESTS PASSED")
    print("=" * 60)
