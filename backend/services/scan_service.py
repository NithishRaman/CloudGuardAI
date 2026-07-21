from backend.scanners.s3_scanner import S3Scanner
from backend.scanners.iam_scanner import IAMScanner
from backend.scanners.ec2_scanner import EC2Scanner
from backend.scanners.cloudtrail_scanner import CloudTrailScanner
from backend.scanners.compliance_scanner import ComplianceScanner

from backend.services.security_engine import (
    calculate_security_score
)

from backend.services.ai_advisor import (
    generate_security_advice
)


# -----------------------------------------
# Risk priority
# -----------------------------------------

RISK_PRIORITY = {

    "CRITICAL": 4,

    "HIGH": 3,

    "MEDIUM": 2,

    "LOW": 1

}


def convert_finding_to_dict(finding):

    """
    Convert SecurityFinding dataclass
    into a normal dictionary.
    """

    if hasattr(
        finding,
        "__dataclass_fields__"
    ):

        return {

            "finding_id":
                finding.finding_id,

            "finding_type":
                finding.finding_type,

            "issue":
                finding.issue,

            "resource":
                finding.resource,

            "risk":
                finding.risk,

            "description":
                finding.description,

            "remediation":
                finding.remediation

        }

    return finding


def get_finding_key(finding):

    """
    Create a unique identity for
    the underlying security issue.

    Example:

    IAM + MFA Disabled + Nithish

    and

    Compliance + IAM MFA Enabled + Nithish

    will be treated as the same
    underlying security issue.
    """

    resource = str(
        finding.get(
            "resource",
            ""
        )
    ).strip().lower()


    issue = str(
        finding.get(
            "issue",
            ""
        )
    ).strip().lower()


    # Normalize MFA findings
    if "mfa" in issue:

        issue = "mfa disabled"


    # Normalize administrator access
    if (
        "administratoraccess"
        in issue
    ):

        issue = (
            "administrator access"
        )


    return (

        issue,

        resource

    )


def deduplicate_security_findings(
    findings
):

    """
    Remove duplicate underlying
    security issues.

    Keeps the highest-risk finding.
    """

    unique_findings = {}


    for finding in findings:

        key = get_finding_key(
            finding
        )


        if key not in unique_findings:

            unique_findings[
                key
            ] = finding

            continue


        existing = unique_findings[
            key
        ]


        existing_risk = RISK_PRIORITY.get(

            str(
                existing.get(
                    "risk",
                    "LOW"
                )
            ).upper(),

            1

        )


        new_risk = RISK_PRIORITY.get(

            str(
                finding.get(
                    "risk",
                    "LOW"
                )
            ).upper(),

            1

        )


        # Keep the higher-risk finding
        if new_risk > existing_risk:

            unique_findings[
                key
            ] = finding


    removed = (

        len(findings)

        - len(
            unique_findings
        )

    )


    print(

        "\nDuplicate underlying "
        "security issues removed:",

        removed

    )


    return list(

        unique_findings.values()

    )


def run_full_scan():

    print(
        "===== CloudGuardAI V2 Full Scan ====="
    )


    # -----------------------------------------
    # S3 Scan
    # -----------------------------------------

    print(
        "\nScanning S3..."
    )


    s3_findings = (
        S3Scanner().scan()
    )


    print(
        "S3 findings:",
        len(s3_findings)
    )


    # -----------------------------------------
    # IAM Scan
    # -----------------------------------------

    print(
        "\nScanning IAM..."
    )


    iam_findings = (
        IAMScanner().scan()
    )


    print(
        "IAM findings:",
        len(iam_findings)
    )


    # -----------------------------------------
    # EC2 Scan
    # -----------------------------------------

    print(
        "\nScanning EC2..."
    )


    ec2_findings = (
        EC2Scanner().scan()
    )


    print(
        "EC2 findings:",
        len(ec2_findings)
    )


    # -----------------------------------------
    # CloudTrail Scan
    # -----------------------------------------

    print(
        "\nScanning CloudTrail..."
    )


    cloudtrail_findings = (
        CloudTrailScanner().scan()
    )


    print(
        "CloudTrail findings:",
        len(cloudtrail_findings)
    )


    # -----------------------------------------
    # Compliance Scan
    # -----------------------------------------

    print(
        "\nScanning Compliance..."
    )


    compliance_findings = (
        ComplianceScanner().scan()
    )


    print(
        "Compliance findings:",
        len(compliance_findings)
    )


    # -----------------------------------------
    # Combine all findings
    # -----------------------------------------

    all_findings = (

        s3_findings

        + iam_findings

        + ec2_findings

        + cloudtrail_findings

        + compliance_findings

    )


    # -----------------------------------------
    # Convert to dictionaries
    # -----------------------------------------

    findings = []


    for finding in all_findings:

        findings.append(

            convert_finding_to_dict(
                finding
            )

        )


    # -----------------------------------------
    # Remove duplicate issues
    # -----------------------------------------

    findings = (
        deduplicate_security_findings(
            findings
        )
    )


    # -----------------------------------------
    # Security Score
    # -----------------------------------------

    score_result = (
        calculate_security_score(
            findings
        )
    )


    # -----------------------------------------
    # AI Security Advisor
    # -----------------------------------------

    print(
        "\nGenerating AI Security Advice..."
    )


    ai_advice = []


    for finding in findings:

        advice = (
            generate_security_advice(
                finding
            )
        )


        ai_advice.append(
            advice
        )


    print(

        "AI Security Advice Generated:",

        len(ai_advice)

    )


    # -----------------------------------------
    # Final Result
    # -----------------------------------------

    result = {

        "project":
            "CloudGuardAI",

        "version":
            "2.0.0",

        "scan_status":
            "completed",

        "summary":
            score_result,

        "findings":
            findings,

        "ai_advice":
            ai_advice

    }


    # -----------------------------------------
    # Final Output
    # -----------------------------------------

    print(
        "\n===== FINAL CLOUDGUARD AI RESULT ====="
    )


    print(

        "Total Findings:",

        len(findings)

    )


    print(

        "Security Score:",

        score_result[
            "security_score"
        ]

    )


    print(

        "Security Grade:",

        score_result[
            "security_grade"
        ]

    )


    return result
