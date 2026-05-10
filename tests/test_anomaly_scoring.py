from src.core.detector import LogAnomalyDetector


def test_anomaly_scoring_is_bounded() -> None:
    detector = LogAnomalyDetector()
    first = detector.score("INFO User 101 logged in from 192.168.1.1")
    second = detector.score("ERROR Connection timeout to database cluster-77")

    assert 0.0 <= first.anomaly_score <= 1.0
    assert 0.0 <= second.anomaly_score <= 1.0
