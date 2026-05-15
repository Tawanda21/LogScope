
---

# LogScope Security Module - Integration Guide

## Overview

This document outlines the security detection modules that will be integrated into LogScope. These detectors work alongside the ML anomaly detection engine to provide comprehensive threat coverage.

---

## What This Module Does

The security module catches **known attack patterns** that traditional ML might miss, while the ML engine catches **novel anomalies** that signature-based detectors would miss. Together they form a complete defense.

| Detection Type | ML Engine | Security Module |
|----------------|-----------|-----------------|
| Known attack signatures | ❌ | ✅ |
| Zero-day exploits | ✅ | ❌ |
| Behavioral anomalies | ✅ | ❌ |
| MITRE ATT&CK mapping | ❌ | ✅ |
| Automated response actions | ❌ | ✅ |

---

## Module Structure

```bash
src/security/
├── __init__.py                    # Module exports
├── detectors/
│   ├── __init__.py
│   ├── brute_force.py            # SSH/FTP/RDP brute force
│   ├── sql_injection.py          # SQL injection patterns
│   ├── priv_esc.py               # Privilege escalation
│   ├── exfiltration.py           # Data exfiltration
│   ├── malware_beacon.py         # C2 beacon detection
│   └── zero_day.py               # Isolation Forest for novel attacks
├── intelligence/
│   ├── __init__.py
│   ├── mitre_mapping.py          # MITRE ATT&CK framework
│   └── ioc_feeds.py              # Threat intelligence integration
├── response/
│   ├── __init__.py
│   ├── firewall.py               # Automatic IP blocking
│   └── alerts.py                 # Slack/PagerDuty integration
└── tests/
    ├── test_brute_force.py
    ├── test_sql_injection.py
    └── test_integration.py
```

---

## Detector Specifications

### 1. SSH Brute Force Detector

**What it detects:** Multiple failed login attempts from same IP

**Input log example:**
```
Failed password for root from 203.0.113.45 port 22 ssh2
pam_unix(sshd:auth): authentication failure; rhost=203.0.113.45
```

**Output format:**
```python
{
    "severity": "HIGH",
    "attack_type": "SSH_BRUTE_FORCE",
    "source_ip": "203.0.113.45",
    "target_user": "root",
    "failed_attempts": 15,
    "time_window_minutes": 5,
    "mitre_technique": "T1110.001 - Password Guessing",
    "recommended_action": "iptables -A INPUT -s 203.0.113.45 -j DROP",
    "confidence": 0.95
}
```

**Detection logic:**
- Track failed attempts per IP over rolling window
- Alert when threshold exceeded (default: 10 attempts in 5 minutes)
- Track attempts per username for targeted attacks

---

### 2. SQL Injection Detector

**What it detects:** Malicious SQL code in web requests

**Input log example:**
```
GET /login?id=1' OR '1'='1 HTTP/1.1
POST /search {"query": "'; DROP TABLE users; --"}
```

**Output format:**
```python
{
    "severity": "CRITICAL",
    "attack_type": "SQL_INJECTION",
    "payload": "1' OR '1'='1",
    "location": "URL parameter 'id'",
    "matched_pattern": "OR \\d+=\\d+",
    "mitre_technique": "T1190 - Exploit Public-Facing Application",
    "recommended_action": "Block request and add to WAF ruleset",
    "confidence": 0.99
}
```

**Detection logic:**
- 15+ regex patterns for SQLi signatures
- Length/entropy anomaly detection for novel variants
- Context-aware detection (GET vs POST)

---

### 3. Privilege Escalation Detector

**What it detects:** Attempts to gain higher system privileges

**Input log example:**
```
sudo: john : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
user alice tried to access /etc/shadow
```

**Output format:**
```python
{
    "severity": "CRITICAL",
    "attack_type": "PRIVILEGE_ESCALATION",
    "user": "john",
    "attempted_command": "/bin/bash",
    "technique": "Sudo abuse to root shell",
    "mitre_technique": "TA0004 - Privilege Escalation",
    "recommended_action": "Revoke sudo rights and investigate user history",
    "confidence": 0.88
}
```

**Detection logic:**
- Monitor sudo commands to shells
- Track setuid binary execution
- Detect PATH hijacking attempts

---

### 4. Data Exfiltration Detector

**What it detects:** Unusual data transfers leaving the network

**Input log example:**
```
USER bob uploaded 50MB to 203.0.113.200 via FTP
Outbound traffic spike: 100Mbps from 10.0.0.45
```

**Output format:**
```python
{
    "severity": "CRITICAL",
    "attack_type": "DATA_EXFILTRATION",
    "user": "bob",
    "bytes_transferred": 52428800,
    "rate_mbps": 8.5,
    "destination_ip": "203.0.113.200",
    "destination_country": "Unknown/External",
    "mitre_technique": "TA0010 - Exfiltration",
    "recommended_action": "Isolate user session and rotate credentials",
    "confidence": 0.92
}
```

**Detection logic:**
- Track bytes per user over time
- Alert on unusual transfer rates
- Flag transfers to unexpected external IPs

---

### 5. Malware Beacon Detector

**What it detects:** Periodic callbacks to C2 servers

**Input log example:**
```
10.0.0.45:54321 -> 185.130.5.253:443 [every 60 seconds]
DNS query: update.windows-defender-sys.com (suspicious TLD)
```

**Output format:**
```python
{
    "severity": "HIGH",
    "attack_type": "C2_BEACONING",
    "source_ip": "10.0.0.45",
    "destination_ip": "185.130.5.253",
    "beacon_interval_seconds": 61,
    "jitter_percentage": 5,
    "mitre_technique": "T1071 - Application Layer Protocol",
    "recommended_action": "Isolate host and capture memory for forensics",
    "confidence": 0.85
}
```

**Detection logic:**
- Detect periodic outbound connections
- Calculate beacon interval and jitter
- Flag suspicious domain patterns

---

### 6. Zero-Day Exploit Detector (Isolation Forest)

**What it detects:** Novel attacks without known signatures

**Input log example:**
```
Any log line that deviates from learned normal patterns
```

**Output format:**
```python
{
    "severity": "CRITICAL",
    "attack_type": "ZERO_DAY_EXPLOIT",
    "anomaly_score": 0.94,
    "confidence": 0.91,
    "features": {
        "length": 847,
        "special_chars": 23,
        "entropy": 6.2,
        "contains_ip": True,
        "contains_url": True
    },
    "mitre_technique": "T1595 - Active Scanning (Unknown)",
    "recommended_action": "Isolate system and preserve full packet capture",
    "note": "No known signature - possible zero-day vulnerability"
}
```

**Detection logic:**
- Train Isolation Forest on normal logs
- Extract 7+ features per log line
- Flag logs that deviate significantly
- No signatures needed - pure ML approach

---

## Integration Bridge

The security module must expose this interface for the ML engine to consume:

```python
# src/security/interface.py

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class SecurityAlert:
    """Standard alert format all detectors must follow"""
    timestamp: datetime
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    attack_type: str
    description: str
    source_ip: Optional[str]
    target_user: Optional[str]
    mitre_technique: Optional[str]
    recommended_action: str
    confidence: float  # 0.0 to 1.0
    raw_log: str
    detector_name: str

class SecurityDetectorInterface:
    """
    All security detectors must implement this interface.
    """
    
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
        Return detector metrics for Prometheus.
        
        Returns:
            Dict with keys: total_processed, alerts_raised, false_positives
        """
        raise NotImplementedError
    
    def update_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Allow dynamic threshold tuning without restart"""
        raise NotImplementedError
```

---

## Metrics to Export (Prometheus)

Each detector must export these metrics:

```python
# Prometheus metrics format
security_bruteforce_attempts_total{source_ip="203.0.113.45"} 47
security_bruteforce_alerts_total{severity="HIGH"} 3
security_sql_injection_alerts_total{pattern="OR_1=1"} 12
security_privilege_escalation_alerts_total{user="john"} 2
security_exfiltration_bytes_total{user="bob"} 104857600
security_zeroday_anomaly_score 0.87
security_beacon_detections_total{source_ip="10.0.0.45"} 1
```

**Export endpoint:** `/metrics` (port 9090)

---

## Alert Routing

When a security alert fires, route to:

| Severity | Action |
|----------|--------|
| **CRITICAL** | Slack #security-alerts + PagerDuty + Block IP |
| **HIGH** | Slack #security-alerts + Create Jira ticket |
| **MEDIUM** | Log to Elasticsearch + Dashboard highlight |
| **LOW** | Store for threat hunting |

**Webhook format for Slack:**
```json
{
    "text": "🔴 *CRITICAL SECURITY ALERT*",
    "blocks": [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Attack Type:* SQL Injection\n*Source IP:* 203.0.113.45\n*MITRE:* T1190\n*Action:* Block immediately"
            }
        }
    ]
}
```

---

## Test Data Requirements

To test the security module, generate these attack scenarios:

```bash
# Generate 1000 normal logs
python generate_logs.py --type normal --count 1000

# Generate 100 attack logs (10 per type)
python generate_logs.py --type attacks --attack_types all --count 100

# Mixed stream (95% normal, 5% attacks)
python generate_logs.py --type mixed --anomaly_rate 0.05
```

**Attack log fixtures** (`tests/fixtures/`):

| File | Contains |
|------|----------|
| `ssh_bruteforce.log` | 50 failed SSH attempts from same IP |
| `sql_injection.log` | 20 SQLi attempts (various patterns) |
| `privilege_escalation.log` | Sudo abuse, setuid attempts |
| `exfiltration.log` | Large outbound transfers |
| `c2_beacon.log` | Periodic connections every 60s |

---

## Acceptance Criteria

The security module is complete when:

- [ ] **All 6 detectors** implemented and tested
- [ ] **95%+ detection rate** on test attack logs
- [ ] **<1% false positive rate** on normal logs
- [ ] **<10ms latency** per log line
- [ ] **MITRE ATT&CK mapping** for all attack types
- [ ] **Prometheus metrics** exported correctly
- [ ] **Integration tests** pass with ML engine
- [ ] **Documentation** includes runbooks for each alert type

---

## Performance Requirements

| Detector | Max Latency | Memory | Accuracy Target |
|----------|-------------|--------|-----------------|
| Brute Force | 2ms | 50MB | 99% precision |
| SQL Injection | 5ms | 30MB | 98% recall |
| Privilege Escalation | 3ms | 40MB | 95% F1 |
| Exfiltration | 4ms | 100MB | 90% detection |
| Beacon Detection | 10ms | 200MB | 85% detection |
| Zero-Day (IF) | 8ms | 150MB | N/A (novel) |

---

## Configuration File

The security module reads from `config/security.yaml`:

```yaml
detectors:
  brute_force:
    enabled: true
    window_minutes: 5
    threshold_attempts: 10
    whitelist_ips: ["10.0.0.0/8", "192.168.0.0/16"]
    
  sql_injection:
    enabled: true
    patterns: "all"  # or "basic" for less false positives
    block_malicious: true
    
  privilege_escalation:
    enabled: true
    monitor_sudo: true
    monitor_setuid: true
    
  exfiltration:
    enabled: true
    bytes_threshold_mb: 10
    rate_threshold_mbps: 5
    internal_networks: ["10.0.0.0/8", "172.16.0.0/12"]
    
  beacon_detection:
    enabled: true
    min_beacon_interval_seconds: 30
    max_jitter_percentage: 20
    
  zero_day:
    enabled: true
    contamination: 0.05
    retrain_interval_hours: 24

alerting:
  slack_webhook: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  pagerduty_integration_key: "your-key-here"
  
mitre:
  enabled: true
  api_key: "optional-mitre-api-key"
```

---

## Testing Your Integration

Run this test script to verify the security module works:

```python
# tests/test_security_integration.py

import pytest
from src.security import SecurityOrchestrator
from src.integration.security_bridge import SecurityBridge

def test_brute_force_detection():
    """Test that 10 failed SSH attempts trigger alert"""
    detector = SecurityOrchestrator()
    
    attack_logs = [
        "Failed password for root from 203.0.113.45 port 22 ssh2"
        for _ in range(10)
    ]
    
    alerts = []
    for log in attack_logs:
        result = detector.analyze_log(log)
        if result:
            alerts.extend(result)
    
    assert len(alerts) >= 1
    assert alerts[0]['attack_type'] == 'SSH_BRUTE_FORCE'
    assert alerts[0]['source_ip'] == '203.0.113.45'

def test_sql_injection_patterns():
    """Test SQL injection detection works"""
    detector = SecurityOrchestrator()
    
    malicious_log = "GET /user?id=1' UNION SELECT * FROM users--"
    result = detector.analyze_log(malicious_log)
    
    assert result is not None
    assert result[0]['attack_type'] == 'SQL_INJECTION'

def test_zero_day_detection():
    """Test isolation forest catches novel patterns"""
    detector = SecurityOrchestrator()
    
    # Train on normal logs
    for _ in range(100):
        detector.analyze_log("INFO User login success from 10.0.0.1")
    
    # Test novel pattern
    weird_log = "ERROR\x00\x01\x02Corrupted\xFFpacket\x7F\x00sequence\x1F"
    result = detector.analyze_log(weird_log)
    
    # Should flag as zero-day
    assert result is None or result[0]['attack_type'] == 'ZERO_DAY_EXPLOIT'
```

---

## Deliverables Checklist

When you hand off the security module, include:

- [ ] `src/security/` directory with all detectors
- [ ] `tests/security/` with >80% coverage
- [ ] `config/security.yaml` configuration file
- [ ] `docs/security/runbooks.md` (how to respond to each alert)
- [ ] `docs/security/threat_model.md` (what threats we cover)
- [ ] `examples/attack_generator.py` (for demo purposes)
- [ ] `prometheus/alerts.yml` (Prometheus alert rules)
- [ ] `grafana/dashboards/security.json` (Grafana dashboard)

---

## Quick Start for Development

```bash
# Clone the LogScope repo
git clone https://github.com/yourusername/logscope.git
cd logscope

# Create security branch
git checkout -b feature/security-module

# Install dependencies
pip install scikit-learn pandas numpy pytest

# Create module structure
mkdir -p src/security/detectors
mkdir -p tests/security
mkdir -p config

# Copy the starter code from this README
# Implement detectors one by one

# Run tests
pytest tests/security/ -v --cov=src/security

# Once passing, create PR to main branch
git add .
git commit -m "feat(security): add brute force and SQL injection detectors"
git push origin feature/security-module
```

---

## Questions to Answer Before Starting

1. **Do you need real-time or batch processing?** (Real-time for critical alerts)

2. **What log sources will you monitor?** (SSH, HTTP, sudo, network)

3. **Do you have threat intelligence feeds?** (Can add later)

4. **What's the false positive tolerance?** (Low for automated blocking)

5. **Do you need compliance reporting?** (PCI, HIPAA, SOC2)

---

## Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules for Detection](https://github.com/SigmaHQ/sigma)
- [OWASP Top 10 for Web Attacks](https://owasp.org/www-project-top-ten/)
- [C2 Beacon Detection Paper](https://arxiv.org/abs/2104.11658)

---
