import streamlit as st
import requests
import json
from datetime import datetime


# ============================================================
# CONFIG
# ============================================================

API_URL = "http://127.0.0.1:8000"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CloudGuardAI Security Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# PROFESSIONAL DARK SOC THEME
# ============================================================

st.markdown(
    """
    <style>

    /* Global */

    .stApp {
        background-color: #0b0f14;
        color: #e6edf3;
    }


    /* Sidebar */

    section[data-testid="stSidebar"] {
        background-color: #0f141b;
        border-right: 1px solid #242b35;
    }


    /* Main title */

    .main-title {
        font-size: 34px;
        font-weight: 700;
        letter-spacing: -1px;
        color: #f0f6fc;
    }


    .subtitle {
        color: #8b949e;
        font-size: 15px;
        margin-bottom: 20px;
    }


    /* Cards */

    .metric-card {
        background-color: #111820;
        border: 1px solid #242b35;
        border-radius: 12px;
        padding: 20px;
        min-height: 125px;
    }


    .metric-label {
        color: #8b949e;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }


    .metric-value {
        color: #f0f6fc;
        font-size: 32px;
        font-weight: 700;
        margin-top: 8px;
    }


    /* Section headers */

    .section-title {
        font-size: 20px;
        font-weight: 600;
        margin-top: 30px;
        margin-bottom: 15px;
        color: #f0f6fc;
    }


    /* Alert cards */

    .critical-alert {
        background-color: #211217;
        border: 1px solid #8b2635;
        border-left: 5px solid #f85149;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 10px;
    }


    .high-alert {
        background-color: #211b12;
        border: 1px solid #8b6b26;
        border-left: 5px solid #d29922;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 10px;
    }


    /* Service status */

    .service-card {
        background-color: #111820;
        border: 1px solid #242b35;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }


    .service-name {
        color: #c9d1d9;
        font-size: 14px;
        font-weight: 600;
    }


    .service-status {
        color: #3fb950;
        font-size: 13px;
        margin-top: 5px;
    }


    /* AI Advisor */

    .ai-card {
        background-color: #111820;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
    }


    /* Footer */

    .footer {
        text-align: center;
        color: #6e7681;
        padding: 30px;
        font-size: 12px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "scan_result" not in st.session_state:

    st.session_state.scan_result = None


if "last_scan" not in st.session_state:

    st.session_state.last_scan = None


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "## 🛡️ CloudGuardAI"
    )

    st.caption(
        "Security Command Center"
    )

    st.divider()


    st.markdown(
        "### OVERVIEW"
    )

    st.write(
        "◉  Security Dashboard"
    )


    st.markdown(
        "### SECURITY"
    )

    st.write(
        "◉  Findings"
    )

    st.write(
        "◉  Critical Alerts"
    )


    st.markdown(
        "### INTELLIGENCE"
    )

    st.write(
        "◉  AI Security Advisor"
    )


    st.markdown(
        "### REPORTS"
    )

    st.write(
        "◉  Security Reports"
    )


    st.divider()


    # API Status

    st.markdown(
        "### SYSTEM STATUS"
    )


    try:

        health = requests.get(
            f"{API_URL}/health",
            timeout=5
        )


        if health.status_code == 200:

            st.success(
                "🟢 API Connected"
            )

        else:

            st.warning(
                "🟡 API Unstable"
            )


    except:

        st.error(
            "🔴 API Offline"
        )


    st.divider()


    # Scan button

    if st.button(
        "🔄 RUN SECURITY SCAN",
        use_container_width=True
    ):

        with st.spinner(
            "Scanning AWS environment..."
        ):

            try:

                response = requests.post(
                    f"{API_URL}/scan",
                    timeout=120
                )


                if response.status_code == 200:

                    st.session_state.scan_result = (
                        response.json()
                    )


                    st.session_state.last_scan = (
                        datetime.now()
                    )


                    st.success(
                        "Scan completed successfully."
                    )


                    st.rerun()


                else:

                    st.error(
                        "Scan failed."
                    )


            except Exception as e:

                st.error(
                    "Unable to connect to API."
                )

                st.code(
                    str(e)
                )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">Security Command Center</div>',
    unsafe_allow_html=True
)


st.markdown(
    '<div class="subtitle">'
    'Real-time AWS cloud security posture monitoring and AI-powered threat intelligence'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# EMPTY STATE
# ============================================================

if st.session_state.scan_result is None:

    st.info(
        "No security scan available. "
        "Use **RUN SECURITY SCAN** in the sidebar."
    )

    st.stop()


# ============================================================
# DATA
# ============================================================

result = st.session_state.scan_result


summary = result.get(
    "summary",
    {}
)


score = summary.get(
    "security_score",
    0
)


grade = summary.get(
    "security_grade",
    "F"
)


total = summary.get(
    "total_findings",
    0
)


risk = summary.get(
    "risk_summary",
    {}
)


critical = risk.get(
    "CRITICAL",
    0
)


high = risk.get(
    "HIGH",
    0
)


medium = risk.get(
    "MEDIUM",
    0
)


low = risk.get(
    "LOW",
    0
)


findings = result.get(
    "findings",
    []
)


ai_advice = result.get(
    "ai_advice",
    []
)


# ============================================================
# TOP STATUS BAR
# ============================================================

status_col1, status_col2 = st.columns(
    [4, 1]
)


with status_col1:

    st.caption(
        "AWS ENVIRONMENT"
    )

    st.markdown(
        "🟢 **Connected and Monitoring**"
    )


with status_col2:

    if st.session_state.last_scan:

        st.caption(
            "LAST SCAN"
        )

        st.write(
            st.session_state.last_scan.strftime(
                "%H:%M:%S"
            )
        )


# ============================================================
# SECURITY METRICS
# ============================================================

st.markdown(
    '<div class="section-title">Security Overview</div>',
    unsafe_allow_html=True
)


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.markdown(
        f"""
        <div class="metric-card">
        <div class="metric-label">
        Security Score
        </div>
        <div class="metric-value">
        {score}/100
        </div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col2:

    st.markdown(
        f"""
        <div class="metric-card">
        <div class="metric-label">
        Security Grade
        </div>
        <div class="metric-value">
        {grade}
        </div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col3:

    st.markdown(
        f"""
        <div class="metric-card">
        <div class="metric-label">
        Total Findings
        </div>
        <div class="metric-value">
        {total}
        </div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col4:

    st.markdown(
        f"""
        <div class="metric-card">
        <div class="metric-label">
        Critical Threats
        </div>
        <div class="metric-value">
        {critical}
        </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# SECURITY SCORE
# ============================================================

st.markdown(
    '<div class="section-title">Security Health</div>',
    unsafe_allow_html=True
)


st.progress(
    score / 100
)


st.caption(
    f"Current security posture: {score}%"
)


# ============================================================
# RISK DISTRIBUTION
# ============================================================

st.markdown(
    '<div class="section-title">Risk Distribution</div>',
    unsafe_allow_html=True
)


r1, r2, r3, r4 = st.columns(4)


with r1:

    st.metric(
        "🔴 Critical",
        critical
    )


with r2:

    st.metric(
        "🟠 High",
        high
    )


with r3:

    st.metric(
        "🟡 Medium",
        medium
    )


with r4:

    st.metric(
        "🟢 Low",
        low
    )


# ============================================================
# CRITICAL ALERTS
# ============================================================

priority_findings = [

    f

    for f in findings

    if f.get(
        "risk"
    ) in [
        "CRITICAL",
        "HIGH"
    ]

]


if priority_findings:

    st.markdown(
        '<div class="section-title">🚨 Priority Security Alerts</div>',
        unsafe_allow_html=True
    )


    for finding in priority_findings:

        risk_level = finding.get(
            "risk",
            "HIGH"
        )


        issue = finding.get(
            "issue",
            "Unknown"
        )


        resource = finding.get(
            "resource",
            "Unknown"
        )


        if risk_level == "CRITICAL":

            st.markdown(
                f"""
                <div class="critical-alert">
                <b>🔴 CRITICAL</b><br>
                <b>{issue}</b><br>
                Resource: {resource}
                </div>
                """,
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                f"""
                <div class="high-alert">
                <b>🟠 HIGH RISK</b><br>
                <b>{issue}</b><br>
                Resource: {resource}
                </div>
                """,
                unsafe_allow_html=True
            )


# ============================================================
# AWS SECURITY SERVICES
# ============================================================

st.markdown(
    '<div class="section-title">AWS Security Services</div>',
    unsafe_allow_html=True
)


services = [
    "IAM",
    "S3",
    "EC2",
    "CloudTrail",
    "Compliance"
]


service_cols = st.columns(
    len(services)
)


for col, service in zip(
    service_cols,
    services
):

    with col:

        st.markdown(
            f"""
            <div class="service-card">
            <div class="service-name">
            {service}
            </div>
            <div class="service-status">
            🟢 SCANNED
            </div>
            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================
# AI SECURITY COPILOT
# ============================================================

st.markdown(
    '<div class="section-title">🤖 AI Security Copilot</div>',
    unsafe_allow_html=True
)


if ai_advice:

    immediate = [

        advice

        for advice in ai_advice

        if advice.get(
            "priority"
        ) == "IMMEDIATE"

    ]


    if immediate:

        first_advice = immediate[0]


        st.markdown(
            f"""
            <div class="ai-card">

            <b>🚨 Immediate Attention Required</b>

            <br><br>

            {first_advice.get(
                "analysis",
                "No analysis available."
            )}

            <br><br>

            <b>Recommended Action:</b>

            <br>

            {first_advice.get(
                "recommended_action",
                "No recommendation available."
            )}

            </div>
            """,
            unsafe_allow_html=True
        )


    else:

        st.info(
            "AI Security Copilot analyzed the latest scan."
        )


# ============================================================
# FINDINGS TABLE
# ============================================================

st.markdown(
    '<div class="section-title">📋 Security Findings</div>',
    unsafe_allow_html=True
)


if findings:

    filter_option = st.selectbox(
        "Filter findings",
        [
            "ALL",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ]
    )


    filtered = [

        f

        for f in findings

        if filter_option == "ALL"

        or f.get(
            "risk"
        ) == filter_option

    ]


    for finding in filtered:

        with st.expander(

            f"{finding.get('risk', 'LOW')} | "
            f"{finding.get('issue', 'Unknown')} | "
            f"{finding.get('resource', 'Unknown')}"

        ):

            st.write(
                "**Finding ID:**",
                finding.get(
                    "finding_id"
                )
            )


            st.write(
                "**Type:**",
                finding.get(
                    "finding_type"
                )
            )


            st.write(
                "**Description:**",
                finding.get(
                    "description"
                )
            )


            st.write(
                "**Remediation:**",
                finding.get(
                    "remediation"
                )
            )


# ============================================================
# DOWNLOAD REPORT
# ============================================================

st.markdown(
    '<div class="section-title">📥 Security Report</div>',
    unsafe_allow_html=True
)


st.download_button(

    "Download Full Security Report",

    data=json.dumps(
        result,
        indent=4
    ),

    file_name="CloudGuardAI_Security_Report.json",

    mime="application/json"

)


# ============================================================
# FOOTER
# ============================================================

st.divider()


st.markdown(
    """
    <div class="footer">
    CloudGuardAI V2 · AI-Powered AWS Security Intelligence
    <br>
    FastAPI · Streamlit · AWS · Python
    </div>
    """,
    unsafe_allow_html=True
)
