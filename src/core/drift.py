from __future__ import annotations

try:
    from river.drift import ADWIN
except Exception:  # pragma: no cover - fallback when river is unavailable
    ADWIN = None  # type: ignore[assignment]


class DriftDetector:
    def __init__(self) -> None:
        self._detector = ADWIN() if ADWIN else None
        self._baseline = 0.0
        self._count = 0

    def update(self, value: float) -> bool:
        if self._detector is not None:
            self._detector.update(value)
            return bool(self._detector.drift_detected)

        self._count += 1
        self._baseline = self._baseline + (value - self._baseline) / self._count
        return abs(value - self._baseline) > 0.35 and self._count > 20
