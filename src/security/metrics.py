"""Prometheus metrics for security detection."""

from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry


class SecurityMetrics:
    """Prometheus metrics for security module."""

    def __init__(self, registry: CollectorRegistry = None):
        """Initialize security metrics."""
        self.registry = registry or CollectorRegistry()

        # Counters - total alerts by type
        self.brute_force_alerts = Counter(
            "security_bruteforce_alerts_total",
            "Total SSH brute force alerts",
            registry=self.registry,
        )

        self.sql_injection_alerts = Counter(
            "security_sql_injection_alerts_total",
            "Total SQL injection alerts",
            registry=self.registry,
        )

        self.priv_esc_alerts = Counter(
            "security_priv_esc_alerts_total",
            "Total privilege escalation alerts",
            registry=self.registry,
        )

        self.exfil_alerts = Counter(
            "security_exfiltration_alerts_total",
            "Total data exfiltration alerts",
            registry=self.registry,
        )

        self.beacon_alerts = Counter(
            "security_beacon_alerts_total",
            "Total C2 beacon alerts",
            registry=self.registry,
        )

        # Gauges - current status
        self.active_threats = Gauge(
            "security_active_threats",
            "Number of active threats",
            registry=self.registry,
        )

        self.detection_latency = Histogram(
            "security_detection_latency_ms",
            "Detection latency in milliseconds",
            buckets=(1, 5, 10, 50, 100, 500, 1000),
            registry=self.registry,
        )

    def record_alert(self, alert_type: str) -> None:
        """Record an alert by type."""
        if alert_type == "SSH_BRUTE_FORCE":
            self.brute_force_alerts.inc()
        elif alert_type == "SQL_INJECTION":
            self.sql_injection_alerts.inc()
        elif alert_type == "PRIVILEGE_ESCALATION":
            self.priv_esc_alerts.inc()
        elif alert_type == "DATA_EXFILTRATION":
            self.exfil_alerts.inc()
        elif alert_type == "C2_BEACONING":
            self.beacon_alerts.inc()

    def record_detection_latency(self, latency_ms: float) -> None:
        """Record detection latency."""
        self.detection_latency.observe(latency_ms)

    def set_active_threats(self, count: int) -> None:
        """Set current active threat count."""
        self.active_threats.set(count)
