from __future__ import annotations

from typing import Iterable, List

try:
    import numpy as np
except Exception:  # pragma: no cover - allow running without numpy installed
    np = None

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - fallback when sklearn is unavailable
    IsolationForest = None  # type: ignore[assignment]


class ParameterDetector:
    def __init__(self) -> None:
        self._model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42) if IsolationForest else None
        self._samples: List[np.ndarray] = []
        self._is_fitted = False

    @staticmethod
    def encode(parameters: Iterable[str]):
        values = []
        for parameter in parameters:
            numeric = "".join(character for character in parameter if character.isdigit())
            if numeric:
                values.append(float(numeric[-6:]))
            else:
                values.append(float(sum(ord(character) for character in parameter) % 1000))
        if not values:
            values = [0.0]
        if np is None:
            return values
        return np.asarray(values, dtype=float)

    def update(self, parameters: Iterable[str]) -> None:
        sample = self.encode(parameters)
        self._samples.append(sample)
        if self._model is not None and len(self._samples) >= 10 and np is not None:
            matrix = self._pad_samples(self._samples)
            self._model.fit(matrix)
            self._is_fitted = True

    def score(self, parameters: Iterable[str]) -> float:
        sample = self.encode(parameters)
        if self._model is None or not self._is_fitted or np is None:
            return 0.0

        matrix = self._pad_samples([sample])
        prediction = self._model.decision_function(matrix)[0]
        return float(max(0.0, min(1.0, (0.5 - prediction) + 0.5)))

    @staticmethod
    def _pad_samples(samples: List[np.ndarray]) -> np.ndarray:
        if np is None:
            # Fallback: pad with zeros and return list-of-lists
            width = max(len(sample) for sample in samples)
            matrix = [[0.0] * width for _ in samples]
            for index, sample in enumerate(samples):
                for j, v in enumerate(sample):
                    matrix[index][j] = v
            return matrix

        width = max(sample.shape[0] for sample in samples)
        matrix = np.zeros((len(samples), width), dtype=float)
        for index, sample in enumerate(samples):
            matrix[index, : sample.shape[0]] = sample
        return matrix
