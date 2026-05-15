from __future__ import annotations

import math
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
        self._feature_width = 0

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
            self._feature_width = matrix.shape[1]
            self._is_fitted = True

    def score(self, parameters: Iterable[str]) -> float:
        sample = self.encode(parameters)
        if self._model is None or not self._is_fitted or np is None:
            return 0.0

        width = self._feature_width or getattr(self._model, "n_features_in_", sample.shape[0] if np is not None else len(sample))
        matrix = self._pad_samples([sample], width=width)
        prediction = self._model.decision_function(matrix)[0]
        # Smooth the IsolationForest output instead of clamping it so anomaly scores spread out.
        return float(1.0 / (1.0 + math.exp(6.0 * prediction)))

    @staticmethod
    def _pad_samples(samples: List[np.ndarray], width: int | None = None) -> np.ndarray:
        if np is None:
            # Fallback: pad with zeros and return list-of-lists
            width = width or max(len(sample) for sample in samples)
            matrix = [[0.0] * width for _ in samples]
            for index, sample in enumerate(samples):
                for j, v in enumerate(sample[:width]):
                    matrix[index][j] = v
            return matrix

        width = width or max(sample.shape[0] for sample in samples)
        matrix = np.zeros((len(samples), width), dtype=float)
        for index, sample in enumerate(samples):
            limit = min(sample.shape[0], width)
            matrix[index, :limit] = sample[:limit]
        return matrix
