from collections import Counter
from typing import Any


RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
}

RISK_PENALTIES = {
    "CRITICAL": 20,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 0.5,
}


def get_finding_value(
    finding: Any,
    field: str,
    default=None,
):
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
        default,
    )


def normalize_finding(finding):
    """
    Create a normalized identity for a finding.

    Used for exact duplicate detection.
    """

    finding_type = str(
        get_finding_value(
            finding,
            "finding_type",
            "",
        )
    ).strip().lower()

    issue = str(
        get_finding_value(
            finding,
            "issue",
            "",
        )
    ).strip().lower()

    resource = str(
        get_finding_value(
            finding,
            "resource",
            "",
        )
    ).strip().lower()

    return (
        finding_type,
        issue,
        resource,
    )


def deduplicate_findings(findings):
    """
    Remove exact duplicate security findings.

    Keeps the first occurrence.
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
            f"Duplicate security findings removed: {removed}"
        )

    return list(
        unique_findings.values()
    )


def calculate_risk_summary(findings):
    """
    Count findings by risk level.
    """

    risk_counts = Counter()

    for finding in findings:

        risk = str(
            get_finding_value(
                finding,
                "risk",
                "LOW",
            )
        ).upper().strip()

        if risk not in RISK_WEIGHTS:

            risk = "LOW"

        risk_counts[risk] += 1

    return {
        "CRITICAL": risk_counts.get(
            "CRITICAL",
            0,
        ),
        "HIGH": risk_counts.get(
            "HIGH",
            0,
        ),
        "MEDIUM": risk_counts.get(
            "MEDIUM",
            0,
        ),
        "LOW": risk_counts.get(
            "LOW",
            0,
        ),
    }


def calculate_security_grade(score):
    """
    Convert a security score into a grade.

    Accepts either:
    - A numeric score
    - A result dictionary containing "security_score"
    """

    if isinstance(score, dict):
        score = score.get(
            "security_score",
            0,
        )

    score = float(score)

    if score >= 90:
        return "A"

    if score >= 80:
        return "B"

    if score >= 70:
        return "C"

    if score >= 60:
        return "D"

    return "F"


def calculate_security_score(findings):
    """
    Calculate CloudGuardAI security score.

    Score starts at 100.

    Penalties:
    CRITICAL = 20 points
    HIGH     = 8 points
    MEDIUM   = 3 points
    LOW      = 0.5 points

    Score is always between 0 and 100.
    """

    findings = deduplicate_findings(
        findings
    )

    risk_summary = calculate_risk_summary(
        findings
    )

    penalty = (

        risk_summary["CRITICAL"] * 20

        + risk_summary["HIGH"] * 8

        + risk_summary["MEDIUM"] * 3

        + risk_summary["LOW"] * 0.5

    )

    security_score = round(
        max(
            0,
            min(
                100,
                100 - penalty,
            ),
        )
    )

    security_grade = calculate_security_grade(
        security_score
    )

    return {
        "total_findings": len(
            findings
        ),
        "security_score": security_score,
        "security_grade": security_grade,
        "risk_summary": risk_summary,
    }
