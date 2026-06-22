import json
import subprocess
from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent

RAW_DIR = BASE_DIR / "module_identity_fabric" / "raw"
FABRIC_JSON = BASE_DIR / "module_identity_fabric" / "normalized" / "identity_fabric.json"
QUALITY_JSON = BASE_DIR / "module_identity_quality" / "reports" / "identity_quality_report.json"
RISK_JSON = BASE_DIR / "module_identity_risk" / "reports" / "identity_risk_report.json"

RAW_DIR.mkdir(parents=True, exist_ok=True)

st.set_page_config(
    page_title="TrustShield IAM AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ TrustShield IAM AI")
st.caption("Identity Governance • Access Risk • Data Quality • Audit Evidence")


def save_upload(uploaded_file, path):
    if uploaded_file:
        with open(path, "wb") as f:
            f.write(uploaded_file.getbuffer())


def run_cmd(cmd):
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=BASE_DIR,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def load_json(path):
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_pipeline():
    steps = [
        "python3 module_identity_fabric/src/fabric_engine.py",
        "python3 module_identity_quality/src/quality_engine.py",
        "python3 module_identity_risk/src/risk_engine.py",
    ]

    for step in steps:
        code, out, err = run_cmd(step)
        if code != 0:
            st.error(f"Failed: {step}")
            st.code(err)
            st.stop()


tab1, tab2, tab3, tab4 = st.tabs([
    "Upload & Analyze",
    "Executive Dashboard",
    "Identity Risk Center",
    "Evidence Center"
])

with tab1:
    st.subheader("Upload Raw IAM Data")

    hr_file = st.file_uploader("Upload HR Export CSV", type=["csv"])
    ad_file = st.file_uploader("Upload AD / Entra Export CSV", type=["csv"])
    groups_file = st.file_uploader("Upload Groups Export CSV", type=["csv"])

    if st.button("Run IAM Governance Analysis", use_container_width=True):
        save_upload(hr_file, RAW_DIR / "hr_export.csv")
        save_upload(ad_file, RAW_DIR / "ad_export.csv")
        save_upload(groups_file, RAW_DIR / "groups_export.csv")

        with st.spinner("Running Identity Fabric, Data Quality, and Risk Engines..."):
            run_pipeline()

        st.success("Analysis completed successfully.")

    st.info(
        "If no files are uploaded, the platform uses the existing demo data "
        "inside module_identity_fabric/raw."
    )

with tab2:
    st.subheader("Executive Dashboard")

    quality = load_json(QUALITY_JSON)
    risk = load_json(RISK_JSON)

    if not risk or not quality:
        st.warning("Run analysis first.")
    else:
        risk_summary = risk["summary"]
        quality_summary = quality["summary"]

        governance_score = quality_summary["average_quality_score"]
        governance_score -= risk_summary["critical"] * 8
        governance_score -= risk_summary["high"] * 4
        governance_score -= risk_summary["medium"] * 2
        governance_score = max(0, round(governance_score))

        if governance_score >= 90:
            status = "Excellent"
        elif governance_score >= 75:
            status = "Good"
        elif governance_score >= 60:
            status = "Needs Attention"
        else:
            status = "Poor"

        c1, c2, c3, c4, c5 = st.columns(5)

        c1.metric("Total Identities", risk_summary["total_identities"])
        c2.metric("Critical Risks", risk_summary["critical"])
        c3.metric("High Risks", risk_summary["high"])
        c4.metric("Avg Data Quality", quality_summary["average_quality_score"])
        c5.metric("Governance Health", f"{governance_score}/100", status)

        st.divider()

        chart_df = pd.DataFrame([
            {"Severity": "Critical", "Count": risk_summary["critical"]},
            {"Severity": "High", "Count": risk_summary["high"]},
            {"Severity": "Medium", "Count": risk_summary["medium"]},
            {"Severity": "Low", "Count": risk_summary["low"]},
        ])

        st.subheader("Risk Distribution")
        st.bar_chart(chart_df, x="Severity", y="Count", use_container_width=True)

with tab3:
    st.subheader("Identity Risk Center")

    risk = load_json(RISK_JSON)

    if not risk:
        st.warning("Run analysis first.")
    else:
        identities = risk["identity_risks"]
        df = pd.DataFrame(identities)

        display_df = df[[
            "severity",
            "risk_score",
            "email",
            "name",
            "department",
            "status",
            "signal_count",
            "recommended_action"
        ]]

        st.dataframe(display_df, use_container_width=True, hide_index=True)

        risky = [i for i in identities if i["risk_score"] > 0]

        if risky:
            selected_label = st.selectbox(
                "Select identity for investigation",
                [f"{i['severity']} | {i['risk_score']} | {i['email']}" for i in risky]
            )

            selected_email = selected_label.split(" | ")[2]
            selected = next(i for i in risky if i["email"] == selected_email)

            st.markdown(f"### Investigation: {selected['email']}")

            a, b, c = st.columns(3)
            a.metric("Risk Score", selected["risk_score"])
            b.metric("Severity", selected["severity"])
            c.metric("Signals", selected["signal_count"])

            st.write(f"**Recommended Action:** {selected['recommended_action']}")

            st.subheader("Risk Signals")

            for signal in selected["signals"]:
                with st.expander(f"{signal['signal']} (+{signal['weight']})"):
                    st.write(f"**Category:** {signal['category']}")
                    st.write(signal["explanation"])
                    st.json(signal["evidence"])

with tab4:
    st.subheader("Evidence Center")

    files = [
        ("Identity Fabric JSON", FABRIC_JSON),
        ("Data Quality Report JSON", QUALITY_JSON),
        ("Identity Risk Report JSON", RISK_JSON),
        ("Data Quality Markdown Report", BASE_DIR / "module_identity_quality" / "reports" / "identity_quality_report.md"),
        ("Identity Risk Markdown Report", BASE_DIR / "module_identity_risk" / "reports" / "identity_risk_report.md"),
    ]

    for label, path in files:
        if path.exists():
            st.download_button(
                label=f"Download {label}",
                data=path.read_text(encoding="utf-8"),
                file_name=path.name,
                use_container_width=True
            )
        else:
            st.warning(f"{label} not found.")

    st.info("Evidence files support IAM control validation, audit preparation, and remediation tracking.")
