from src.core.detector import LogAnomalyDetector


def test_detector_returns_result() -> None:
    detector = LogAnomalyDetector()
    result = detector.score("2026-05-10 10:00:00 INFO User 123 logged in from 192.168.1.1")

    assert result.template
    assert 0.0 <= result.anomaly_score <= 1.0
