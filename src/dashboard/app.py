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
    if bool(row.get("review_is_anomaly", row.get("is_anomaly", False))):
        return ["color: #d10000; font-weight: 700;"] * len(row)
    return [""] * len(row)


def highlight_anomaly_score(val: float) -> str:
    """Color anomaly_score column with minimal red text for anomalies."""
    if pd.isna(val):
        return ""
    if val >= 0.40:
        return "color: #d10000; font-weight: 700;"
    return ""


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
review_frame = frame.copy()
review_frame["detector_is_anomaly"] = review_frame["is_anomaly"].astype(bool)
review_frame["review_is_anomaly"] = review_frame["detector_is_anomaly"].astype(bool)
review_frame["status"] = review_frame["review_is_anomaly"].map({True: "ANOMALY", False: "✓ NORMAL"})
review_frame = review_frame.sort_values(["detector_is_anomaly", "anomaly_score"], ascending=[False, False]).reset_index(drop=True)

st.caption("Use the review_is_anomaly checkboxes to override the detector when you want to review a row manually.")

edited_frame = st.data_editor(
    review_frame,
    hide_index=True,
    use_container_width=True,
    key="anomaly_review_editor",
    disabled=[column for column in review_frame.columns if column != "review_is_anomaly"],
    column_config={
        "detector_is_anomaly": st.column_config.CheckboxColumn(
            "detector_is_anomaly",
            help="Detector output. Read-only reference.",
            disabled=True,
        ),
        "review_is_anomaly": st.column_config.CheckboxColumn(
            "review_is_anomaly",
            help="Editable review flag used for the summary and highlighted table.",
        ),
        "status": st.column_config.TextColumn("status", help="Final review status."),
        "explanation": st.column_config.TextColumn("explanation", width="large"),
    },
)

current_frame = edited_frame.copy()
current_frame["review_is_anomaly"] = current_frame["review_is_anomaly"].astype(bool)
current_frame["is_anomaly"] = current_frame["review_is_anomaly"]
current_frame["status"] = current_frame["review_is_anomaly"].map({True: "ANOMALY", False: "✓ NORMAL"})

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Logs", len(current_frame))
with col2:
    anomaly_count = current_frame["review_is_anomaly"].sum()
    st.metric("Anomalies Detected", anomaly_count)
with col3:
    max_score = current_frame["anomaly_score"].max()
    st.metric("Max Anomaly Score", f"{max_score:.3f}")

st.subheader("Highlighted Results")
display_styled = current_frame.style.apply(highlight_anomalies, axis=1)
display_styled = display_styled.map(lambda x: highlight_anomaly_score(x) if isinstance(x, (int, float)) else "", subset=["anomaly_score"])
st.dataframe(display_styled, use_container_width=True)

anomaly_rows = current_frame[current_frame["review_is_anomaly"]]
if not anomaly_rows.empty:
    st.subheader(f"Detected Anomalies ({len(anomaly_rows)} found)")
    anomaly_styled = anomaly_rows.style.apply(highlight_anomalies, axis=1)
    anomaly_styled = anomaly_styled.map(lambda x: highlight_anomaly_score(x) if isinstance(x, (int, float)) else "", subset=["anomaly_score"])
    st.dataframe(anomaly_styled, use_container_width=True)

st.subheader("Anomaly Score Timeline with Threshold")
chart_data = frame[["anomaly_score", "frequency_score", "parameter_score", "sequence_score"]].copy()
chart_data["Anomaly Threshold (0.40)"] = 0.40
st.line_chart(chart_data)

st.divider()
st.caption("🔴 Red cells = anomaly detected (score ≥ 0.40) | Emoji badges show detection summary")

