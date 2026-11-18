import hashlib
import sqlite3
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = Path("sentinelguard_web.db")

st.set_page_config(page_title="SentinelGuard", page_icon="🛡️", layout="wide")

def timestamp():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT NOT NULL,
        event_type TEXT NOT NULL,
        file_name TEXT NOT NULL,
        old_hash TEXT,
        new_hash TEXT,
        details TEXT
    )""")
    conn.commit()
    return conn

def record_events(events):
    conn = init_db()
    try:
        conn.executemany(
            """INSERT INTO audit_log
            (event_time,event_type,file_name,old_hash,new_hash,details)
            VALUES (?,?,?,?,?,?)""",
            [(timestamp(), *event) for event in events],
        )
        conn.commit()
    finally:
        conn.close()

def load_logs(limit=500):
    conn = init_db()
    try:
        return pd.read_sql_query(
            "SELECT event_time,event_type,file_name,old_hash,new_hash,details "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            conn, params=(limit,)
        )
    finally:
        conn.close()

st.markdown("""
<style>
.stApp {background: #0e1726;}
.block-container {padding-top: 2rem; max-width: 1400px;}
[data-testid="stMetric"] {background:#172438; border:1px solid #263b56; padding:16px; border-radius:12px;}
div[data-testid="stDataFrame"] {border:1px solid #263b56; border-radius:10px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ SentinelGuard")
st.caption("File Integrity Monitoring System · SHA-256 · SQLite Audit Trail")
st.info("Web demo: upload the files you are authorized to monitor. The cloud app cannot directly access folders on your personal computer.")

uploaded = st.file_uploader(
    "Upload the current snapshot of your monitored files",
    type=None,
    accept_multiple_files=True,
    help="Upload one or more files. Keep the same relative file names when uploading a later snapshot."
)

current = {}
if uploaded:
    for item in uploaded:
        current[item.name] = {
            "sha256": sha256_bytes(item.getvalue()),
            "size": len(item.getvalue()),
        }

if "baseline" not in st.session_state:
    st.session_state.baseline = None
if "last_counts" not in st.session_state:
    st.session_state.last_counts = None

left, right = st.columns([1, 1])
with left:
    if st.button("Create trusted baseline", type="primary", use_container_width=True, disabled=not current):
        st.session_state.baseline = current.copy()
        record_events([("BASELINE_CREATED", "Uploaded snapshot", None, None,
                        f"Trusted baseline created for {len(current)} file(s).")])
        st.success(f"Baseline created for {len(current)} file(s).")
with right:
    if st.button("Scan for changes", use_container_width=True, disabled=not current or st.session_state.baseline is None):
        baseline = st.session_state.baseline
        counts = {"ADDED": 0, "MODIFIED": 0, "DELETED": 0, "UNCHANGED": 0}
        events = []
        for name, info in current.items():
            if name not in baseline:
                counts["ADDED"] += 1
                events.append(("ADDED", name, None, info["sha256"], "File was not present in the trusted baseline."))
            elif baseline[name]["sha256"] != info["sha256"]:
                counts["MODIFIED"] += 1
                events.append(("MODIFIED", name, baseline[name]["sha256"], info["sha256"], "SHA-256 hash differs from baseline."))
            else:
                counts["UNCHANGED"] += 1
        for name, info in baseline.items():
            if name not in current:
                counts["DELETED"] += 1
                events.append(("DELETED", name, info["sha256"], None, "File was present in baseline but is now missing."))
        if events:
            record_events(events)
        st.session_state.last_counts = counts
        st.session_state.last_events = events
        st.rerun()

st.divider()
st.subheader("Security overview")
counts = st.session_state.last_counts or {"ADDED": 0, "MODIFIED": 0, "DELETED": 0, "UNCHANGED": 0}
metrics = st.columns(4)
for col, label, color in zip(metrics, counts, ["#2d9d78", "#d49a35", "#d45c67", "#477eae"]):
    col.metric(label, counts[label])

if st.session_state.baseline is None:
    st.warning("No trusted baseline yet. Upload files and click 'Create trusted baseline'.")
else:
    st.success(f"Trusted baseline loaded: {len(st.session_state.baseline)} file(s).")

if st.session_state.get("last_events"):
    st.subheader("Latest scan findings")
    st.dataframe(pd.DataFrame(st.session_state.last_events,
                 columns=["Event", "File", "Previous SHA-256", "Current SHA-256", "Details"]),
                 use_container_width=True, hide_index=True)

st.divider()
st.subheader("Audit history")
logs = load_logs()
if logs.empty:
    st.caption("No audit events recorded yet.")
else:
    st.dataframe(logs, use_container_width=True, hide_index=True)
    st.download_button("Download audit log (CSV)", logs.to_csv(index=False).encode("utf-8"),
                       file_name="sentinelguard_audit.csv", mime="text/csv")

with st.expander("How this web demo works"):
    st.markdown("""
    1. Upload the files that form your initial trusted snapshot.
    2. Create a baseline; SentinelGuard stores each file's SHA-256 hash.
    3. Upload a later snapshot using the same filenames.
    4. Scan to identify additions, modifications, deletions and unchanged files.
    5. Review timestamped events and export the audit log.

    **Deployment note:** This hosted demo can only inspect files uploaded to it. It cannot continuously watch your laptop's local folders. The hosted SQLite database may be reset by the hosting platform when the app is redeployed or its storage is recycled.
    """)
