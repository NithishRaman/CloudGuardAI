from collections import Counter


# Risk weights
RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
}


def get_finding_value(finding, field, default=None):
    """
    Safely read a field from either:
    - SecurityFinding object
    - Dictionary
    """

    if isinstance(finding, dict):
        return finding.get(field, default)

    return getattr(
        finding,
        field,
        default
    )


def normalize_finding(finding):
    """
    Create a normalized identity for a finding.
    """

    finding_type = str(
        get_finding_value(
            finding,
            "finding_type",
            ""
        )
    ).strip().lower()

    issue = str(
        get_finding_value(
            finding,
            "issue",
            ""
        )
    ).strip().lower()

    resource = str(
        get_finding_value(
            finding,
            "resource",
            ""
        )
    ).strip().lower()

    return (
        finding_type,
        issue,
        resource
    )


def deduplicate_findings(findings):
    """
    Remove duplicate security findings.
    """

    unique_findings = {}

    for finding in findings:

        key = normalize_finding(
            finding
        )

        if key not in unique_findings:

            unique_findings[key] = finding

    removed = (
        len(findings)
        - len(unique_findings)
    )

    if removed > 0:

        print(
            f"Duplicate security issues removed: {removed}"
        )

    return list(
        unique_findings.values()
    )


def calculate_security_score(findings):
    """
    Calculate CloudGuardAI security score.

    Score starts at 100.

    Risk penalties:
    CRITICAL = 20 points
    HIGH     = 8 points
    MEDIUM   = 3 points
    LOW      = 0.5 points

    The score is always between 0 and 100.
    """

    # Remove duplicate findings
    findings = deduplicate_findings(
        findings
    )

    # Count risks
    risk_counts = Counter()

    for finding in findings:

        risk = str(
            get_finding_value(
                finding,
                "risk",
                "LOW"
            )
        ).upper().strip()

        if risk not in RISK_WEIGHTS:

            risk = "LOW"

        risk_counts[risk] += 1

    # --------------------------------
    # Calculate penalty
    # --------------------------------

    penalty = (

        risk_counts.get(
            "CRITICAL",
            0
        ) * 20

        + risk_counts.get(
            "HIGH",
            0
        ) * 8

        + risk_counts.get(
            "MEDIUM",
            0
        ) * 3

        + risk_counts.get(
            "LOW",
            0
        ) * 0.5

    )

    # --------------------------------
    # Calculate score
    # --------------------------------

    security_score = round(
        max(
            0,
            min(
                100,
                100 - penalty
            )
        )
    )

    # --------------------------------
    # Calculate grade
    # --------------------------------

    if security_score >= 90:

        security_grade = "A"

    elif security_score >= 80:

        security_grade = "B"

    elif security_score >= 70:

        security_grade = "C"

    elif security_score >= 60:

        security_grade = "D"

    else:

        security_grade = "F"

    # --------------------------------
    # Return result
    # --------------------------------

    return {

        "total_findings": len(
            findings
        ),

        "security_score": security_score,

        "security_grade": security_grade,

        "risk_summary": {

            "CRITICAL": risk_counts.get(
                "CRITICAL",
                0
            ),

            "HIGH": risk_counts.get(
                "HIGH",
                0
            ),

            "MEDIUM": risk_counts.get(
                "MEDIUM",
                0
            ),

            "LOW": risk_counts.get(
                "LOW",
                0
            ),

        },

    }
