from __future__ import annotations

from collections import deque
from pathlib import Path

import pandas as pd
import streamlit as st

from src.core.detector import LogAnomalyDetector
from src.data.live_log_generator import start_background_generator


st.set_page_config(page_title="LogScope Dashboard", layout="wide")
st.title("LogScope")
st.caption("Real-time log anomaly detection with live streaming data.")


# Initialize session state for log generator
if "log_generator_started" not in st.session_state:
    st.session_state.log_generator_started = False
    # Start the background log generator
    live_logs_path = Path(__file__).resolve().parents[1] / "data" / "live_logs.csv"
    start_background_generator(
        output_file=str(live_logs_path),
        log_interval=2.0,  # New log batch every 2 seconds
        batch_size=1,  # 1 log per batch
    )
    st.session_state.log_generator_started = True


def load_live_logs(max_rows: int = 50) -> pd.DataFrame:
    """Load live logs from the continuously-updated CSV file."""
    live_logs_path = Path(__file__).resolve().parents[1] / "data" / "live_logs.csv"
    
    if live_logs_path.exists():
        df = pd.read_csv(live_logs_path)
        # Return the latest max_rows entries
        return df.tail(max_rows).reset_index(drop=True)
    
    return pd.DataFrame()


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

# Load live logs and process them
live_data = load_live_logs(max_rows=50)

if not live_data.empty:
    st.write(f"Live logs: {len(live_data)} rows loaded (latest entries)")
    
    # Convert live logs to detector format and score them
    sample_logs = []
    for _, row in live_data.iterrows():
        # Format log entry as a string for the detector
        log_entry = (
            f"{row.get('timestamp', 'N/A')} "
            f"{row.get('method', 'N/A')} "
            f"{row.get('endpoint', 'N/A')} "
            f"from {row.get('ip_address', 'N/A')} "
            f"status={row.get('status_code', 'N/A')} "
            f"time={row.get('response_time_ms', 'N/A')}ms "
            f"size={row.get('response_size_bytes', 'N/A')}B"
        )
        sample_logs.append(log_entry)
    
    for entry in sample_logs:
        history.append(detector.score(entry).model_dump())
    
    # Add auto-refresh
    st.markdown("""
    <script>
    setTimeout(function() {
        document.body.style.opacity = "0.98";
    }, 1000);
    </script>
    """, unsafe_allow_html=True)
    st.info("Dashboard auto-refreshes as new logs arrive. Streamlit will reload in 10 seconds.")
else:
    st.warning("⏳ Waiting for live logs... The log generator is starting up. Check back in a moment.")
    st.stop()

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
st.caption("Red cells = anomaly detected (score ≥ 0.40) | Emoji badges show detection summary")

# Auto-refresh mechanism
col1, col2 = st.columns([1, 1])
with col1:
    if st.button("Refresh Now"):
        st.rerun()

with col2:
    st.info("Auto-reloading every 10 seconds for live updates...")
    
# JavaScript auto-refresh (10 seconds)
st.markdown("""
<script>
setTimeout(function() {
    document.querySelector('[data-testid="stApp"]').dispatchEvent(new Event('sessionStateRerun'));
    location.reload();
}, 10000);
</script>
""", unsafe_allow_html=True)


