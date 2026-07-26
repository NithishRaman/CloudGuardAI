from backend.models.finding import SecurityFinding

from backend.services.security_engine import (
    calculate_security_score,
    calculate_risk_summary,
    calculate_security_grade,
)


def make_findings():
    return [
        SecurityFinding(
            finding_id="IAM-001",
            finding_type="IAM",
            issue="MFA Disabled",
            resource="cloudguard-admin",
            risk="HIGH",
        ),
        SecurityFinding(
            finding_id="IAM-002",
            finding_type="IAM",
            issue="Administrator Access",
            resource="cloudguard-admin",
            risk="CRITICAL",
        ),
        SecurityFinding(
            finding_id="S3-001",
            finding_type="S3",
            issue="Public Access Risk",
            resource="example-bucket",
            risk="MEDIUM",
        ),
    ]


def test_calculate_risk_summary():

    findings = make_findings()

    summary = calculate_risk_summary(
        findings
    )

    assert summary["CRITICAL"] == 1
    assert summary["HIGH"] == 1
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 0


def test_calculate_security_score():

    findings = make_findings()

    result = calculate_security_score(
        findings
    )

    assert result["total_findings"] == 3

    assert result["security_score"] == 69

    assert result["security_grade"] == "D"


def test_calculate_security_grade():

    assert calculate_security_grade(95) == "A"

    assert calculate_security_grade(85) == "B"

    assert calculate_security_grade(75) == "C"

    assert calculate_security_grade(65) == "D"

    assert calculate_security_grade(50) == "F"


def test_calculate_security_grade_from_result():

    result = {
        "security_score": 85
    }

    assert (
        calculate_security_grade(result)
        == "B"
    )


def test_empty_findings():

    result = calculate_security_score(
        []
    )

    assert result["total_findings"] == 0

    assert result["security_score"] == 100

    assert result["security_grade"] == "A"


def test_duplicate_findings_are_removed():

    finding = SecurityFinding(
        finding_id="IAM-001",
        finding_type="IAM",
        issue="MFA Disabled",
        resource="cloudguard-admin",
        risk="HIGH",
    )

    result = calculate_security_score(
        [
            finding,
            finding,
        ]
    )

    assert result["total_findings"] == 1

    assert result["risk_summary"]["HIGH"] == 1
