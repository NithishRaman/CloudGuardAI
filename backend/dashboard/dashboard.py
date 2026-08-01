import os
from collections import Counter
from datetime import datetime

import requests
import streamlit as st


# ============================================================
# CLOUDGUARDAI PROFESSIONAL SECURITY DASHBOARD
# ============================================================

st.set_page_config(
    page_title="CloudGuardAI | AWS Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CONFIGURATION
# ============================================================

# Streamlit Cloud can override this with an Environment Variable.
# Default points to the deployed Vercel FastAPI backend.

API_URL = os.getenv(
    "API_URL",
    "https://cloud-guard-ai-seven.vercel.app",
).rstrip("/")


# ============================================================
# PROFESSIONAL CSS
# ============================================================

st.markdown(
    """
    <style>

    .stApp {
        background:
            radial-gradient(
                circle at top right,
                rgba(37, 99, 235, 0.08),
                transparent 30%
            ),
            #070b12;
        color: #e5e7eb;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    h1, h2, h3, h4 {
        color: #f8fafc !important;
    }

    p {
        color: #94a3b8;
    }

    section[data-testid="stSidebar"] {
        background: #090d14;
        border-right: 1px solid #1e293b;
    }

    section[data-testid="stSidebar"] h1 {
        font-size: 22px;
    }

    .brand {
        font-size: 30px;
        font-weight: 800;
        letter-spacing: -1px;
        color: #f8fafc;
    }

    .brand span {
        color: #60a5fa;
    }

    .subtitle {
        color: #64748b;
        font-size: 14px;
        margin-top: -8px;
    }

    .status-online {
        display: inline-block;
        padding: 7px 14px;
        border-radius: 999px;
        background: rgba(34, 197, 94, 0.10);
        border: 1px solid rgba(34, 197, 94, 0.25);
        color: #4ade80;
        font-size: 12px;
        font-weight: 700;
    }

    .status-offline {
        display: inline-block;
        padding: 7px 14px;
        border-radius: 999px;
        background: rgba(239, 68, 68, 0.10);
        border: 1px solid rgba(239, 68, 68, 0.25);
        color: #f87171;
        font-size: 12px;
        font-weight: 700;
    }

    .hero {
        padding: 28px;
        border-radius: 18px;
        border: 1px solid #1e293b;
        background:
            linear-gradient(
                135deg,
                rgba(15, 23, 42, 0.95),
                rgba(10, 15, 25, 0.95)
            );
        margin-bottom: 25px;
    }

    .hero-eyebrow {
        color: #60a5fa;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    .hero-title {
        font-size: 38px;
        font-weight: 800;
        letter-spacing: -1.5px;
        margin-top: 8px;
        color: #f8fafc;
    }

    .hero-description {
        max-width: 700px;
        color: #94a3b8;
        font-size: 15px;
        margin-top: 8px;
    }

    .card {
        background: #0d131d;
        border: 1px solid #1e293b;
        border-radius: 16px;
        padding: 22px;
        height: 100%;
    }

    .card-title {
        color: #94a3b8;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    .card-value {
        color: #f8fafc;
        font-size: 34px;
        font-weight: 800;
        margin-top: 8px;
    }

    .card-description {
        color: #64748b;
        font-size: 12px;
        margin-top: 5px;
    }

    .score-card {
        background:
            linear-gradient(
                145deg,
                #101827,
                #0b1018
            );
        border: 1px solid #263449;
        border-radius: 18px;
        padding: 28px;
        text-align: center;
        height: 100%;
    }

    .score-label {
        color: #64748b;
        font-size: 11px;
        letter-spacing: 2px;
        font-weight: 700;
    }

    .score {
        font-size: 72px;
        font-weight: 900;
        color: #f87171;
        line-height: 1;
        margin: 15px 0;
    }

    .score span {
        font-size: 22px;
        color: #64748b;
    }

    .grade {
        color: #f87171;
        font-weight: 800;
        font-size: 14px;
        letter-spacing: 1px;
    }

    .severity-critical {
        color: #f87171;
    }

    .severity-high {
        color: #fb923c;
    }

    .severity-medium {
        color: #facc15;
    }

    .severity-low {
        color: #4ade80;
    }

    .severity-card {
        background: #0d131d;
        border: 1px solid #1e293b;
        border-radius: 16px;
        padding: 20px;
        text-align: center;
    }

    .severity-label {
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 1px;
    }

    .severity-number {
        font-size: 38px;
        font-weight: 900;
        margin-top: 8px;
    }

    .finding {
        background: #0d131d;
        border: 1px solid #1e293b;
        border-radius: 14px;
        padding: 18px;
        margin-bottom: 12px;
    }

    .finding-title {
        color: #f8fafc;
        font-size: 15px;
        font-weight: 700;
    }

    .finding-resource {
        color: #64748b;
        font-size: 12px;
        margin-top: 5px;
    }

    .finding-description {
        color: #94a3b8;
        font-size: 13px;
        margin-top: 10px;
    }

    .badge {
        display: inline-block;
        padding: 4px 9px;
        border-radius: 5px;
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 0.5px;
    }

    .badge-critical {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
    }

    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #fb923c;
    }

    .badge-medium {
        background: rgba(234, 179, 8, 0.15);
        color: #facc15;
    }

    .badge-low {
        background: rgba(34, 197, 94, 0.15);
        color: #4ade80;
    }

    .ai-card {
        background:
            linear-gradient(
                135deg,
                rgba(30, 41, 59, 0.8),
                rgba(15, 23, 42, 0.8)
            );
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 22px;
    }

    .ai-label {
        color: #60a5fa;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 1.5px;
    }

    .ai-title {
        color: #f8fafc;
        font-size: 20px;
        font-weight: 800;
        margin-top: 8px;
    }

    .ai-text {
        color: #94a3b8;
        font-size: 13px;
        margin-top: 8px;
        line-height: 1.6;
    }

    .ai-action {
        margin-top: 15px;
        padding: 14px;
        border-radius: 10px;
        background: rgba(37, 99, 235, 0.10);
        border: 1px solid rgba(37, 99, 235, 0.20);
        color: #bfdbfe;
        font-size: 13px;
    }

    .service-card {
        background: #0d131d;
        border: 1px solid #1e293b;
        border-radius: 14px;
        padding: 18px;
        text-align: center;
    }

    .service-icon {
        font-size: 25px;
    }

    .service-name {
        color: #f8fafc;
        font-weight: 700;
        margin-top: 8px;
    }

    .service-status {
        color: #4ade80;
        font-size: 10px;
        font-weight: 700;
        margin-top: 5px;
    }

    .stButton > button {
        border-radius: 10px;
        font-weight: 700;
        min-height: 45px;
    }

    hr {
        border-color: #1e293b !important;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if "last_scan" not in st.session_state:
    st.session_state.last_scan = "Never"


# ============================================================
# API FUNCTIONS
# ============================================================

def check_api():
    """
    Check the deployed FastAPI backend.

    Backend endpoint:
        GET https://cloud-guard-ai-seven.vercel.app/health
    """

    try:
        response = requests.get(
            f"{API_URL}/health",
            timeout=10,
        )

        return response.status_code < 400

    except requests.RequestException:
        return False


def run_scan():
    """
    Run AWS security scan through FastAPI.

    Backend endpoint:
        POST https://cloud-guard-ai-seven.vercel.app/scan
    """

    try:
        response = requests.post(
            f"{API_URL}/scan",
            timeout=120,
        )

        response.raise_for_status()

        return response.json()

    except requests.ConnectionError:
        st.error(
            "Cannot connect to the CloudGuardAI API."
        )
        return None

    except requests.Timeout:
        st.error(
            "The security scan timed out."
        )
        return None

    except requests.HTTPError as e:
        try:
            detail = response.json()
        except Exception:
            detail = response.text

        st.error(
            f"API returned an error: {e}"
        )

        st.code(
            str(detail),
            language="json",
        )

        return None

    except requests.RequestException as e:
        st.error(
            f"API request failed: {e}"
        )
        return None

    except ValueError:
        st.error(
            "The API returned an invalid JSON response."
        )
        return None


# ============================================================
# DATA HELPERS
# ============================================================

def get_value(data, *keys, default=None):

    if not isinstance(data, dict):
        return default

    for key in keys:
        if key in data:
            return data[key]

    return default


def normalize_findings(data):

    if not isinstance(data, dict):
        return []

    findings = get_value(
        data,
        "findings",
        "security_findings",
        "results",
        default=[],
    )

    if not isinstance(findings, list):
        return []

    return findings


def get_severity(finding):

    if not isinstance(finding, dict):
        return "LOW"

    severity = get_value(
        finding,
        "risk",
        "severity",
        "level",
        default="LOW",
    )

    severity = str(
        severity
    ).strip().upper()

    if severity not in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]:
        return "LOW"

    return severity


def get_finding_name(finding):

    return str(
        get_value(
            finding,
            "issue",
            "title",
            "finding",
            "name",
            default="Security Finding",
        )
    )


def get_resource(finding):

    return str(
        get_value(
            finding,
            "resource",
            "resource_name",
            "resource_id",
            "user",
            "principal",
            default="Unknown",
        )
    )


def get_description(finding):

    return str(
        get_value(
            finding,
            "description",
            "details",
            "message",
            default="",
        )
    )


def get_remediation(finding):

    return str(
        get_value(
            finding,
            "remediation",
            "recommendation",
            "recommended_action",
            default=(
                "Review this finding and apply "
                "the recommended security control."
            ),
        )
    )


def is_cloudtrail_finding(finding):

    if not isinstance(finding, dict):
        return False

    finding_type = str(
        finding.get(
            "finding_type",
            "",
        )
    ).lower()

    issue = str(
        finding.get(
            "issue",
            "",
        )
    ).lower()

    return (
        finding_type == "cloudtrail"
        or "cloudtrail" in issue
    )


def calculate_counts(findings):

    counts = Counter()

    for finding in findings:
        counts[get_severity(finding)] += 1

    return counts


def get_score(data):

    if not isinstance(data, dict):
        return 0

    summary = data.get(
        "summary",
        {},
    )

    if isinstance(summary, dict):

        score = summary.get(
            "security_score",
            None,
        )

        if score is not None:
            try:
                return int(score)
            except (TypeError, ValueError):
                pass

    score = get_value(
        data,
        "security_score",
        "score",
        default=0,
    )

    try:
        return int(score)
    except (TypeError, ValueError):
        return 0


def get_grade(data):

    if not isinstance(data, dict):
        return "F"

    summary = data.get(
        "summary",
        {},
    )

    if isinstance(summary, dict):

        grade = summary.get(
            "security_grade",
            None,
        )

        if grade is not None:
            return str(grade).upper()

    grade = get_value(
        data,
        "security_grade",
        "grade",
        default="F",
    )

    return str(grade).upper()


# ============================================================
# HEADER
# ============================================================

api_online = check_api()

header_col1, header_col2 = st.columns(
    [4, 1]
)

with header_col1:

    st.markdown(
        """
        <div class="brand">
        🛡️ CloudGuard<span>AI</span>
        </div>

        <div class="subtitle">
        AI-Powered AWS Security Intelligence Platform
        </div>
        """,
        unsafe_allow_html=True,
    )


with header_col2:

    if api_online:

        st.markdown(
            """
            <div class="status-online">
            ● API CONNECTED
            </div>
            """,
            unsafe_allow_html=True,
        )

    else:

        st.markdown(
            """
            <div class="status-offline">
            ● API OFFLINE
            </div>
            """,
            unsafe_allow_html=True,
        )


st.divider()


# ============================================================
# HERO
# ============================================================

st.markdown(
    """
    <div class="hero">

    <div class="hero-eyebrow">
    CLOUD SECURITY INTELLIGENCE
    </div>

    <div class="hero-title">
    Your AWS environment. Secured by intelligence.
    </div>

    <div class="hero-description">
    Continuous security posture monitoring, threat detection,
    compliance analysis, and AI-powered remediation intelligence.
    </div>

    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SCAN CONTROL
# ============================================================

scan_col1, scan_col2, scan_col3 = st.columns(
    [2, 2, 1]
)

with scan_col1:

    st.markdown(
        f"**Last Security Scan:** `{st.session_state.last_scan}`"
    )


with scan_col2:

    st.markdown(
        "**Environment:** `AWS · CONNECTED`"
    )


with scan_col3:

    if st.button(
        "⚡ RUN SECURITY SCAN",
        use_container_width=True,
    ):

        if not api_online:

            st.error(
                "CloudGuardAI API is offline."
            )

        else:

            with st.spinner(
                "Scanning AWS environment..."
            ):

                result = run_scan()

                if result:

                    st.session_state.scan_result = result

                    st.session_state.last_scan = (
                        datetime.now().strftime(
                            "%H:%M:%S"
                        )
                    )

                    st.success(
                        "Security scan completed."
                    )

                    st.rerun()


# ============================================================
# LOAD SCAN DATA
# ============================================================

data = st.session_state.scan_result

all_findings = (
    normalize_findings(data)
    if data
    else []
)


# ============================================================
# SEPARATE SECURITY FINDINGS
# ============================================================

security_findings = [
    finding
    for finding in all_findings
    if not is_cloudtrail_finding(finding)
]


cloudtrail_findings = [
    finding
    for finding in all_findings
    if is_cloudtrail_finding(finding)
]


# ============================================================
# SUMMARY
# ============================================================

summary = {}

if isinstance(data, dict):

    summary = data.get(
        "summary",
        {},
    )

if not isinstance(summary, dict):
    summary = {}


# ============================================================
# TOTAL FINDINGS
# ============================================================

try:

    total_findings = int(
        summary.get(
            "total_findings",
            len(security_findings),
        )
    )

except (TypeError, ValueError):

    total_findings = len(
        security_findings
    )


# ============================================================
# SECURITY SCORE
# ============================================================

security_score = get_score(data)


# ============================================================
# SECURITY GRADE
# ============================================================

security_grade = get_grade(data)


# ============================================================
# RISK SUMMARY
# ============================================================

risk_summary = summary.get(
    "risk_summary",
    {},
)

if not isinstance(
    risk_summary,
    dict,
):

    risk_summary = {}


# Support both uppercase and lowercase API responses.

def risk_count(name):

    value = risk_summary.get(
        name,
        risk_summary.get(
            name.lower(),
            0,
        ),
    )

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


critical_count = risk_count(
    "CRITICAL"
)

high_count = risk_count(
    "HIGH"
)

medium_count = risk_count(
    "MEDIUM"
)

low_count = risk_count(
    "LOW"
)


# ============================================================
# FALLBACK COUNTS
# ============================================================

# If the API doesn't provide risk_summary,
# calculate it directly from the findings.

if (
    critical_count == 0
    and high_count == 0
    and medium_count == 0
    and low_count == 0
    and security_findings
):

    counts = calculate_counts(
        security_findings
    )

    critical_count = counts["CRITICAL"]
    high_count = counts["HIGH"]
    medium_count = counts["MEDIUM"]
    low_count = counts["LOW"]


# ============================================================
# SECURITY POSTURE
# ============================================================

st.markdown(
    "## Security Posture"
)

st.caption(
    "Real-time overview of your AWS security health."
)


score_col, severity_col = st.columns(
    [1, 2]
)


with score_col:

    st.markdown(
        f"""
        <div class="score-card">

        <div class="score-label">
        CURRENT SECURITY POSTURE
        </div>

        <div class="score">
        {security_score}<span>/100</span>
        </div>

        <div class="grade">
        SECURITY GRADE · {security_grade}
        </div>

        <br>

        <div class="card-description">
        CloudGuardAI identified
        <b>{total_findings}</b>
        real security findings.
        </div>

        </div>
        """,
        unsafe_allow_html=True,
    )


with severity_col:

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.markdown(
            f"""
            <div class="severity-card">

            <div class="severity-label severity-critical">
            🔴 CRITICAL
            </div>

            <div class="severity-number severity-critical">
            {critical_count}
            </div>

            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:

        st.markdown(
            f"""
            <div class="severity-card">

            <div class="severity-label severity-high">
            🟠 HIGH
            </div>

            <div class="severity-number severity-high">
            {high_count}
            </div>

            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:

        st.markdown(
            f"""
            <div class="severity-card">

            <div class="severity-label severity-medium">
            🟡 MEDIUM
            </div>

            <div class="severity-number severity-medium">
            {medium_count}
            </div>

            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:

        st.markdown(
            f"""
            <div class="severity-card">

            <div class="severity-label severity-low">
            🟢 LOW
            </div>

            <div class="severity-number severity-low">
            {low_count}
            </div>

            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# THREAT RESPONSE
# ============================================================

st.markdown(
    "## Threat Response"
)

st.caption(
    "Priority security risks requiring attention."
)


priority_findings = [
    finding
    for finding in security_findings
    if get_severity(finding)
    in [
        "CRITICAL",
        "HIGH",
    ]
]


if not priority_findings:

    st.success(
        "No critical or high-risk findings detected."
    )

else:

    for finding in priority_findings[:10]:

        severity = get_severity(
            finding
        )

        name = get_finding_name(
            finding
        )

        resource = get_resource(
            finding
        )

        description = get_description(
            finding
        )

        badge_class = (
            "badge-critical"
            if severity == "CRITICAL"
            else "badge-high"
        )

        st.markdown(
            f"""
            <div class="finding">

            <span class="badge {badge_class}">
            {severity}
            </span>

            <div class="finding-title">
            {name}
            </div>

            <div class="finding-resource">
            Resource · {resource}
            </div>

            <div class="finding-description">
            {description}
            </div>

            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# AI SECURITY COPILOT
# ============================================================

st.markdown(
    "## AI Security Copilot"
)

ai_findings = [
    finding
    for finding in security_findings
    if get_severity(finding)
    in [
        "CRITICAL",
        "HIGH",
    ]
]


if ai_findings:

    ai_finding = ai_findings[0]

    ai_name = get_finding_name(
        ai_finding
    )

    ai_description = get_description(
        ai_finding
    )

    ai_remediation = get_remediation(
        ai_finding
    )

    st.markdown(
        f"""
        <div class="ai-card">

        <div class="ai-label">
        🤖 AI SECURITY COPILOT · PRIORITY ANALYSIS
        </div>

        <div class="ai-title">
        {ai_name}
        </div>

        <div class="ai-text">
        {ai_description}
        </div>

        <div class="ai-action">

        <b>Recommended Action</b>

        <br><br>

        {ai_remediation}

        </div>

        </div>
        """,
        unsafe_allow_html=True,
    )

else:

    st.info(
        "AI Security Copilot has no priority findings to analyze."
    )


# ============================================================
# AWS SECURITY COVERAGE
# ============================================================

st.markdown(
    "## AWS Security Coverage"
)

st.caption(
    "Security services monitored by CloudGuardAI."
)


services = [
    ("🔐", "IAM"),
    ("🪣", "S3"),
    ("🖥️", "EC2"),
    ("📜", "CloudTrail"),
    ("✅", "Compliance"),
]


service_cols = st.columns(
    len(services)
)


for col, service in zip(
    service_cols,
    services,
):

    icon, name = service

    with col:

        st.markdown(
            f"""
            <div class="service-card">

            <div class="service-icon">
            {icon}
            </div>

            <div class="service-name">
            {name}
            </div>

            <div class="service-status">
            ● SCANNED
            </div>

            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# CLOUD ACTIVITY
# ============================================================

st.markdown(
    "## Cloud Activity Intelligence"
)

st.caption(
    "AWS activity analyzed by CloudGuardAI."
)


activity_col1, activity_col2, activity_col3 = st.columns(
    3
)


with activity_col1:

    st.markdown(
        f"""
        <div class="card">

        <div class="card-title">
        CLOUDTRAIL EVENTS
        </div>

        <div class="card-value">
        {len(cloudtrail_findings)}
        </div>

        <div class="card-description">
        AWS activity records analyzed
        </div>

        </div>
        """,
        unsafe_allow_html=True,
    )


with activity_col2:

    st.markdown(
        f"""
        <div class="card">

        <div class="card-title">
        SECURITY FINDINGS
        </div>

        <div class="card-value">
        {len(security_findings)}
        </div>

        <div class="card-description">
        Real security issues detected
        </div>

        </div>
        """,
        unsafe_allow_html=True,
    )


with activity_col3:

    st.markdown(
        f"""
        <div class="card">

        <div class="card-title">
        TOTAL SCAN RESULTS
        </div>

        <div class="card-value">
        {len(all_findings)}
        </div>

        <div class="card-description">
        Combined security and activity results
        </div>

        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.markdown(
    "## Threat Intelligence"
)

st.caption(
    "Investigate security findings detected across your AWS environment."
)


filter_col1, filter_col2 = st.columns(
    [1, 3]
)


with filter_col1:

    severity_filter = st.selectbox(
        "Severity",
        [
            "ALL",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
        ],
    )


with filter_col2:

    search = st.text_input(
        "Search findings",
        placeholder="Search finding or resource...",
    )


filtered_findings = security_findings


if severity_filter != "ALL":

    filtered_findings = [
        finding
        for finding in filtered_findings
        if get_severity(finding)
        == severity_filter
    ]


if search:

    search_lower = search.lower()

    filtered_findings = [
        finding
        for finding in filtered_findings
        if search_lower in (
            get_finding_name(finding)
            + " "
            + get_resource(finding)
            + " "
            + get_description(finding)
        ).lower()
    ]


st.caption(
    f"Showing {len(filtered_findings)} security findings"
)


# ============================================================
# FINDINGS
# ============================================================

if not filtered_findings:

    st.info(
        "No security findings match your filters."
    )

else:

    for finding in filtered_findings:

        severity = get_severity(
            finding
        )

        name = get_finding_name(
            finding
        )

        resource = get_resource(
            finding
        )

        description = get_description(
            finding
        )

        remediation = get_remediation(
            finding
        )

        badge_class = (
            "badge-critical"
            if severity == "CRITICAL"
            else "badge-high"
            if severity == "HIGH"
            else "badge-medium"
            if severity == "MEDIUM"
            else "badge-low"
        )

        with st.expander(
            f"{severity} · {name} · {resource}"
        ):

            st.markdown(
                f"""
                <span class="badge {badge_class}">
                {severity}
                </span>
                """,
                unsafe_allow_html=True,
            )

            st.write(
                f"**Resource:** {resource}"
            )

            st.write(
                f"**Description:** {description}"
            )

            st.write(
                f"**Recommended Action:** {remediation}"
            )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
    <div style="text-align:center; color:#475569; font-size:12px;">

    🛡️ <b>CloudGuardAI</b>
    · AI-Powered AWS Security Intelligence

    <br><br>

    FastAPI · Streamlit · AWS · Python

    </div>
    """,
    unsafe_allow_html=True,
)
