"""Streamlit dashboard for real-time log anomaly detection."""

from pathlib import Path

import pandas as pd
import streamlit as st

from src.core.detector import LogAnomalyDetector
from src.data.live_log_generator import start_background_generator


st.set_page_config(page_title="LogScope Dashboard", layout="wide")
st.title("LogScope")
st.caption("Real-time log anomaly detection with live streaming data.")


# Initialize log generator in background
if "log_generator_started" not in st.session_state:
    live_logs_path = Path(__file__).resolve().parents[1] / "data" / "live_logs.csv"
    start_background_generator(
        output_file=str(live_logs_path),
        log_interval=2.0,
        batch_size=1,
    )
    st.session_state.log_generator_started = True


def load_live_logs(max_rows: int = 50) -> pd.DataFrame:
    """Load latest live logs from CSV."""
    live_logs_path = Path(__file__).resolve().parents[1] / "data" / "live_logs.csv"
    if live_logs_path.exists():
        df = pd.read_csv(live_logs_path)
        return df.tail(max_rows).reset_index(drop=True)
    return pd.DataFrame()


def highlight_anomalies(row: pd.Series) -> list[str]:
    """Highlight anomaly rows in red."""
    if bool(row.get("detector_is_anomaly", False)):
        return ["color: #d10000; font-weight: 700;"] * len(row)
    return [""] * len(row)


def highlight_score(val: float) -> str:
    """Highlight high anomaly scores."""
    if pd.isna(val):
        return ""
    return "color: #d10000; font-weight: 700;" if val >= 0.40 else ""


# Load logs
live_data = load_live_logs(max_rows=50)

if live_data.empty:
    st.warning("⏳ Waiting for live logs... generator starting")
    st.stop()

st.metric("Live Logs", len(live_data))

# Score with detector
detector = LogAnomalyDetector()
results = []

for _, row in live_data.iterrows():
    log_str = (
        f"{row['timestamp']} {row['method']} {row['endpoint']} "
        f"from {row['ip_address']} status={row['status_code']} "
        f"time={row['response_time_ms']}ms"
    )
    try:
        result = detector.score(log_str)
        results.append(result.model_dump())
    except Exception as e:
        st.error(f"Scoring error: {e}")
        st.stop()

detections_df = pd.DataFrame(results)

# Merge source data + detection results
display_frame = live_data.copy()
display_frame["detector_is_anomaly"] = detections_df["is_anomaly"]
display_frame["anomaly_score"] = detections_df["anomaly_score"]
display_frame["frequency_score"] = detections_df["frequency_score"]
display_frame["parameter_score"] = detections_df["parameter_score"]
display_frame["sequence_score"] = detections_df["sequence_score"]
display_frame["explanation"] = detections_df["explanation"]

# Add manual review column
display_frame["review_is_anomaly"] = display_frame["detector_is_anomaly"].copy()
display_frame = display_frame.sort_values(
    ["detector_is_anomaly", "anomaly_score"],
    ascending=[False, False],
).reset_index(drop=True)

# Data editor
st.caption("✏️ Tick review_is_anomaly to manually override detector.")
cols_to_show = [
    "timestamp", "ip_address", "method", "endpoint", "status_code",
    "response_time_ms", "detector_is_anomaly", "review_is_anomaly",
    "anomaly_score", "explanation",
]
cols_to_show = [c for c in cols_to_show if c in display_frame.columns]

edited = st.data_editor(
    display_frame[cols_to_show],
    hide_index=True,
    use_container_width=True,
    key="review_editor",
    disabled=[c for c in cols_to_show if c != "review_is_anomaly"],
    column_config={
        "detector_is_anomaly": st.column_config.CheckboxColumn("detector_is_anomaly", disabled=True),
        "review_is_anomaly": st.column_config.CheckboxColumn("review_is_anomaly"),
        "explanation": st.column_config.TextColumn("explanation", width="large"),
    },
)

# Metrics
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total", len(edited))
with col2:
    st.metric("Anomalies", edited["review_is_anomaly"].sum())
with col3:
    max_score = edited["anomaly_score"].max() if not pd.isna(edited["anomaly_score"]).all() else 0.0
    st.metric("Max Score", f"{max_score:.3f}")

# Results
st.subheader("🔍 All Logs")
styled = edited.style.apply(highlight_anomalies, axis=1).map(
    lambda x: highlight_score(x) if isinstance(x, (int, float)) else "",
    subset=["anomaly_score"],
)
st.dataframe(styled, use_container_width=True)

# Anomalies only
anomalies = edited[edited["review_is_anomaly"]]
if not anomalies.empty:
    st.subheader(f"🚨 Anomalies ({len(anomalies)} found)")
    styled_anom = anomalies.style.apply(highlight_anomalies, axis=1).map(
        lambda x: highlight_score(x) if isinstance(x, (int, float)) else "",
        subset=["anomaly_score"],
    )
    st.dataframe(styled_anom, use_container_width=True)

# Chart
st.subheader("📊 Scores Over Time")
chart_data = display_frame[["anomaly_score", "frequency_score", "parameter_score", "sequence_score"]].copy()
chart_data["Threshold"] = 0.40
st.line_chart(chart_data)

st.divider()
if st.button("🔄 Refresh"):
    st.rerun()
