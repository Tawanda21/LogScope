"""Security detectors module."""

from src.security.detectors.brute_force import BruteForceDetector
from src.security.detectors.exfiltration import ExfiltrationDetector
from src.security.detectors.malware_beacon import BeaconDetectionDetector
from src.security.detectors.priv_esc import PrivilegeEscalationDetector
from src.security.detectors.sql_injection import SQLInjectionDetector

__all__ = [
    "BruteForceDetector",
    "SQLInjectionDetector",
    "PrivilegeEscalationDetector",
    "ExfiltrationDetector",
    "BeaconDetectionDetector",
]
