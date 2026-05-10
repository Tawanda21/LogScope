from __future__ import annotations

from collections import deque
from pathlib import Path

import pandas as pd
import streamlit as st

from src.core.detector import LogAnomalyDetector


st.set_page_config(page_title="LogScope Dashboard", layout="wide")
st.title("LogScope")
st.caption("Synthetic scaffold for streaming log anomaly inspection.")


def load_synthetic_rows() -> pd.DataFrame:
    data_path = Path(__file__).resolve().parents[1] / "data" / "synthetic_logs.csv"
    if data_path.exists():
        return pd.read_csv(data_path)
    return pd.DataFrame(
        [
            {
                "timestamp": "2026-05-10 10:00:00",
                "level": "INFO",
                "user_id": 1234,
                "source_ip": "192.168.1.8",
                "event": "User logged in",
                "anomaly": False,
            },
            {
                "timestamp": "2026-05-10 10:00:01",
                "level": "INFO",
                "user_id": 4321,
                "source_ip": "192.168.1.11",
                "event": "Viewed account overview",
                "anomaly": False,
            },
            {
                "timestamp": "2026-05-10 10:00:02",
                "level": "ERROR",
                "user_id": 7777,
                "source_ip": "10.0.0.77",
                "event": "Connection timeout to database",
                "anomaly": True,
            },
        ]
    )


def highlight_anomalies(row: pd.Series) -> list[str]:
    if bool(row.get("is_anomaly", False)):
        return ["background-color: #ffd6d6; color: #8b0000; font-weight: 700;"] * len(row)
    return [""] * len(row)


detector = LogAnomalyDetector()
history = deque(maxlen=50)

data = load_synthetic_rows()
st.write(f"Loaded {len(data)} synthetic log rows.")

sample_logs = [
    f"{row.timestamp} {row.level} User {row.user_id} from {row.source_ip} - {row.event}"
    for row in data.itertuples(index=False)
]

for entry in sample_logs:
    history.append(detector.score(entry).model_dump())

frame = pd.DataFrame(history)
display_frame = frame.copy()
display_frame["is_anomaly"] = display_frame["is_anomaly"].astype(bool)
display_frame["row_type"] = display_frame["is_anomaly"].map({True: "ANOMALY", False: "normal"})
display_frame = display_frame.sort_values(["is_anomaly", "anomaly_score"], ascending=[False, False]).reset_index(drop=True)

st.dataframe(display_frame.style.apply(highlight_anomalies, axis=1), use_container_width=True)

anomaly_rows = display_frame[display_frame["is_anomaly"]]
if not anomaly_rows.empty:
    st.subheader("Detected anomalies")
    st.dataframe(anomaly_rows.style.apply(highlight_anomalies, axis=1), use_container_width=True)

st.line_chart(frame[["anomaly_score", "frequency_score", "parameter_score", "sequence_score"]])

