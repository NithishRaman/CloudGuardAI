from backend.models.finding import SecurityFinding

from backend.services.security_engine import (
    calculate_security_score,
    calculate_risk_summary,
    calculate_security_grade,
)


findings = [
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


score = calculate_security_score(findings)

summary = calculate_risk_summary(findings)

grade = calculate_security_grade(score)


print("Security Score:", score)

print("Security Grade:", grade)

print("Risk Summary:", summary)
