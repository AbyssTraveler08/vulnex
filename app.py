import streamlit as st
import time
import socket

from utils import validate_ip
from scanner import run_nmap
from cve_fetcher import fetch_cves
from risk_engine import rank_vulnerabilities
from graph_generator import generate_risk_chart
from report_generator import generate_pdf_report
from remediation_engine import get_remediation
from logger import log_event


# ---------------------------
# Helper
# ---------------------------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# ---------------------------
# Streamlit UI
# ---------------------------

st.set_page_config(page_title="Vulnerability Scanner", layout="wide")

st.title("VUNLNEX:- VULNerabilities EXaminer")
st.warning("⚠ Educational use only. Scan devices you own or have permission to scan.")

# Target selection
scan_option = st.radio(
    "Choose Target:",
    ["Scan this device", "Scan another device"]
)

if scan_option == "Scan this device":
    target_ip = get_local_ip()
    st.success(f"Detected Local IP: {target_ip}")
else:
    target_ip = st.text_input("Enter Target IP")

# Scan mode
mode = st.radio(
    "Scan Mode:",
    ["Quick Scan", "Deep Scan"]
)

mode_value = "1" if mode == "Quick Scan" else "2"


# ---------------------------
# Start Scan Button
# ---------------------------

if st.button("🚀 Start Scan"):

    if not target_ip:
        st.error("Please enter a target IP")
        st.stop()

    if scan_option == "Scan another device" and not validate_ip(target_ip):
        st.error("Invalid IP format")
        st.stop()

    log_event(f"Scan started on {target_ip}")

    st.markdown("### 🔍 Scan Progress")

    progress_bar = st.progress(0)
    status_text = st.empty()

    # Step 1: Initialize
    status_text.text("Initializing scan...")
    progress_bar.progress(10)
    time.sleep(0.5)

    # Step 2: Run Nmap
    status_text.text("Running Nmap port scan...")
    progress_bar.progress(30)

    scan_data = run_nmap(target_ip, mode_value)

    progress_bar.progress(60)

    st.success("Nmap Scan Completed")
    st.write("Detected OS:", scan_data.get("os", "Unknown"))

    # Step 3: Fetch CVEs
    status_text.text("Fetching CVEs from NVD database...")
    vulns = fetch_cves(scan_data.get("ports", []))

    progress_bar.progress(75)

    # Step 4: Rank vulnerabilities
    status_text.text("Ranking vulnerabilities...")
    ranked = rank_vulnerabilities(vulns)

    for v in ranked:
        v["fix"] = get_remediation(v["service"])

    progress_bar.progress(85)

    # Step 5: Generate risk chart
    status_text.text("Generating risk visualization...")
    chart_file = generate_risk_chart(ranked)

    progress_bar.progress(95)

    # Step 6: Generate report
    status_text.text("Generating PDF report...")
    report_file = generate_pdf_report(target_ip, scan_data, ranked)

    progress_bar.progress(100)
    status_text.text("Scan completed successfully!")

    log_event("Scan completed")

    # ---------------------------
    # Display Results
    # ---------------------------

    st.subheader("📊 Vulnerability Results")

    if ranked:
        st.dataframe(ranked)

        st.image(chart_file, caption="Risk Distribution")

        with open(report_file, "rb") as f:
            st.download_button(
                label="📄 Download PDF Report",
                data=f,
                file_name="vulnerability_report.pdf",
                mime="application/pdf"
            )
    else:
        st.success("No vulnerabilities found 🎉")