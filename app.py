import streamlit as st
import ollama
import pandas as pd
import glob
import os
import json
from datetime import datetime

# Optional EVTX support
try:
    from Evtx.Evtx import Evtx
    EVTX_AVAILABLE = True
except:
    EVTX_AVAILABLE = False

# ===================== CONFIG =====================
st.set_page_config(
    page_title="Ollama SOC Analyst",
    page_icon="🛡️",
    layout="wide"
)

st.title(" Ollama SOC Analyst")
st.caption("Stable • Offline • AI-powered SOC log analyzer")

# ===================== HELPERS =====================

def read_csv_safely(path):
    encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']

    for enc in encodings:
        try:
            df = pd.read_csv(path, encoding=enc, sep=None, engine='python', low_memory=False)
            st.warning(f" Encoding detected: {enc}")
            return df
        except:
            continue

    # fallback (corrupted CSV)
    with open(path, 'rb') as f:
        content = f.read()

    content = content.replace(b'\x00', b'')
    text = content.decode('latin-1', errors='ignore')
    lines = text.splitlines()

    st.warning(" Used fallback parser (corrupted CSV)")
    return pd.DataFrame(lines, columns=["raw_log"])


def read_evtx_file(path):
    if not EVTX_AVAILABLE:
        raise Exception("Install python-evtx: pip install python-evtx")

    log_text = ""
    with Evtx(path) as log:
        for record in log.records():
            log_text += record.xml() + "\n"
    return log_text


def read_log_file(path):
    if path.lower().endswith(".csv"):
        df = read_csv_safely(path)
        return df.to_string(index=False)

    elif path.lower().endswith(".evtx"):
        return read_evtx_file(path)

    else:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()


def trim_logs(log_text):
    """Prevent Ollama crash"""
    lines = log_text.split("\n")

    # Keep last 200 lines (safe for gemma3:4b)
    trimmed = "\n".join(lines[-200:])

    # Hard safety cap
    if len(trimmed) > 12000:
        trimmed = trimmed[:12000]

    return trimmed


# ===================== SIDEBAR =====================
with st.sidebar:
    st.header("⚙️ Configuration")

    # Fetch models
    try:
        models = [m.model for m in ollama.list().models]
    except:
        models = ["gemma3:4b"]

    model = st.selectbox("Ollama Model", models)

    default_dir = st.text_input(
        "Log Directory",
        value=os.path.join(os.path.expanduser("~"), "OneDrive", "Documents", "security-logs")
    )

    context = st.text_area(
        "Environment Context",
        value="""Location: Pune, India
Working hours: 8AM-6PM
Internal IP: 192.168.x.x
No expected login failures after hours""",
        height=150
    )

    debug = st.checkbox("Enable Debug Mode")


# ===================== TABS =====================
tab1, tab2 = st.tabs([" Analyze Logs", " Results"])


# ===================== ANALYSIS =====================
with tab1:

    if st.button("🔍 Auto-Scan & Analyze", use_container_width=True):

        with st.spinner("Scanning logs..."):

            if not os.path.exists(default_dir):
                st.error(f" Directory not found:\n{default_dir}")
                st.stop()

            files = sorted(
                glob.glob(os.path.join(default_dir, "**/*.*"), recursive=True),
                key=os.path.getmtime,
                reverse=True
            )[:10]

            valid_ext = ('.csv', '.log', '.txt', '.evtx')
            files = [f for f in files if f.lower().endswith(valid_ext)]

            if debug:
                st.write(" Path:", default_dir)
                st.write(" Files:", files)

            if not files:
                st.error(" No log files found")
                st.stop()

            latest_file = files[0]

            st.success(f" Found {len(files)} file(s)")
            st.info(f"Analyzing: {os.path.basename(latest_file)}")

            try:
                log_text = read_log_file(latest_file)
                log_text = trim_logs(log_text)

            except Exception as e:
                st.error(f" File read error: {e}")
                st.stop()

        # ===================== OLLAMA =====================
        with st.spinner(" Running SOC analysis..."):

            system_prompt = """You are a senior SOC analyst.

Respond ONLY in valid JSON:

{
  "summary": "",
  "risk_score": 1-10,
  "timeline": [],
  "suspicious_activities": [],
  "root_cause_hypothesis": "",
  "containment_steps": [],
  "playbook": ""
}
"""

            user_prompt = f"""
Environment:
{context}

Logs:
{log_text}
"""

            try:
                response = ollama.chat(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    options={
                        "temperature": 0.2,
                        "num_ctx": 2048
                    }
                )

                output = response['message']['content']

                try:
                    result = json.loads(output)
                    st.session_state['result'] = result
                    st.success(" Analysis complete")

                except:
                    st.error(" JSON parsing failed")
                    st.code(output)

            except Exception as e:
                st.error(f" Ollama error: {e}")
                st.warning(" Switching to fallback model...")

                #  FALLBACK MODEL
                try:
                    response = ollama.chat(
                        model="llama3:latest",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        options={"temperature": 0.2, "num_ctx": 2048}
                    )

                    output = response['message']['content']
                    result = json.loads(output)

                    st.session_state['result'] = result
                    st.success(" Analysis complete (fallback model)")

                except Exception as e2:
                    st.error(f" Fallback also failed: {e2}")


# ===================== RESULTS =====================
with tab2:

    if 'result' not in st.session_state:
        st.info("Run analysis first ")
    else:
        r = st.session_state['result']

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Risk Score", f"{r.get('risk_score', 'N/A')}/10")

        with col2:
            st.metric("Time", datetime.now().strftime("%H:%M"))

        st.subheader(" Summary")
        st.write(r.get("summary", ""))

        st.subheader(" Timeline")
        for t in r.get("timeline", []):
            st.write(f"• {t}")

        st.subheader(" Suspicious Activities")
        for t in r.get("suspicious_activities", []):
            st.write(f"• {t}")

        st.subheader(" Root Cause")
        st.info(r.get("root_cause_hypothesis", ""))

        st.subheader("🛠 Containment")
        for step in r.get("containment_steps", []):
            st.write(f" {step}")

        st.subheader(" Playbook")
        st.markdown(r.get("playbook", ""))

        st.download_button(
            "⬇ Download JSON Report",
            json.dumps(r, indent=2),
            file_name="soc_report.json"
        )

st.caption("Built with ❤️ • Stable SOC AI • Offline")