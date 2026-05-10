from src.logscope import LogMonitor


def test_logmonitor_process_returns_tuple():
    monitor = LogMonitor()
    is_anomaly, explanation = monitor.process("2026-05-10 10:00:00 INFO User 1 logged in from 192.168.1.1")
    assert isinstance(is_anomaly, bool)
    assert isinstance(explanation, str)
