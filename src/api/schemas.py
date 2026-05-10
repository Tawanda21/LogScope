from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    message: str
    source: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    template: str
    parameters: List[str] = Field(default_factory=list)
    frequency_score: float = 0.0
    parameter_score: float = 0.0
    sequence_score: float = 0.0
    drift_score: float = 0.0
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    explanation: str = ""


class StreamMessage(BaseModel):
    type: str
    payload: Dict[str, Any]
