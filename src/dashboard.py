import streamlit as st
import json
import pandas as pd
import plotly.express as px

from ai_advisor import generate_advice
from remediation_engine import generate_fix


# -----------------------------
# Page Setup
# -----------------------------

st.set_page_config(
    page_title="CloudGuardAI",
    page_icon="🛡️",
    layout="wide"
)



# -----------------------------
# Load Report
# -----------------------------

with open(
    "FINAL_CLOUDGUARD_AI_REPORT.json",
    "r"
) as file:

    report = json.load(file)



# -----------------------------
# Header
# -----------------------------

st.title("🛡️ CloudGuardAI Security Dashboard")

st.write(
    "AWS Cloud Security Posture Monitoring Platform"
)


st.divider()



# -----------------------------
# Security Score
# -----------------------------

score = report.get(
    "security_score",
    0
)

grade = report.get(
    "security_grade",
    "N/A"
)


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Security Score",
        f"{score}/100"
    )


with col2:

    st.metric(
        "Security Grade",
        grade
    )


with col3:

    st.metric(
        "Total Findings",
        report.get(
            "total_findings",
            0
        )
    )



st.divider()



# -----------------------------
# Risk Summary
# -----------------------------

st.subheader("Risk Summary")


risk = report.get(
    "risk_summary",
    {}
)


c1, c2, c3, c4 = st.columns(4)


with c1:

    st.metric(
        "Critical",
        risk.get("CRITICAL",0)
    )


with c2:

    st.metric(
        "High",
        risk.get("HIGH",0)
    )


with c3:

    st.metric(
        "Medium",
        risk.get("MEDIUM",0)
    )


with c4:

    st.metric(
        "Low",
        risk.get("LOW",0)
    )



# -----------------------------
# Risk Chart
# -----------------------------

st.subheader("Risk Distribution")


risk_df = pd.DataFrame({

    "Risk": list(risk.keys()),

    "Count": list(risk.values())

})


fig = px.pie(

    risk_df,

    names="Risk",

    values="Count",

    title="CloudGuardAI Risk Overview"

)


st.plotly_chart(fig)



st.divider()



# -----------------------------
# Compliance
# -----------------------------

st.subheader("🛡️ Compliance Checks")


for finding in report["findings"]:


    if finding.get("type") == "Compliance":


        status = finding.get(
            "status"
        )


        if status == "PASS":

            st.success(

                str(
                    finding.get("issue")
                )
                +
                " : PASS"

            )


        else:

            st.error(

                str(
                    finding.get("issue")
                )
                +
                " : FAIL"

            )



st.divider()



# -----------------------------
# Findings + AI + Remediation
# -----------------------------

st.subheader("Security Findings")


for finding in report["findings"]:


    title = (

        finding.get("issue")

        or

        finding.get("event")

        or

        "Security Finding"

    )


    risk_level = finding.get(
        "risk",
        "UNKNOWN"
    )


    with st.expander(
        f"{risk_level} - {title}"
    ):


        st.json(
            finding
        )


        st.info(
            generate_advice(finding)
        )


        fix = generate_fix(
            finding
        )


        st.warning(
            "Recommended Fix: "
            +
            fix["action"]
        )


        st.code(
            fix["command"]
        )



st.divider()



st.success(
    "CloudGuardAI Monitoring Completed Successfully 🚀"
)
