from backend.scanners.s3_scanner import S3Scanner
from backend.scanners.iam_scanner import IAMScanner
from backend.scanners.ec2_scanner import EC2Scanner
from backend.scanners.cloudtrail_scanner import CloudTrailScanner
from backend.scanners.compliance_scanner import ComplianceScanner

from backend.services.security_engine import (
    calculate_security_score,
)

from backend.services.ai_advisor import (
    generate_security_advice,
)


def convert_finding_to_dict(finding):
    """
    Convert a SecurityFinding dataclass into a dictionary.
    """

    if hasattr(finding, "__dataclass_fields__"):
        return {
            "finding_id": finding.finding_id,
            "finding_type": finding.finding_type,
            "issue": finding.issue,
            "resource": finding.resource,
            "risk": finding.risk,
            "description": finding.description,
            "remediation": finding.remediation,
        }

    return finding


def is_cloudtrail_finding(finding):
    """
    Identify CloudTrail activity separately from
    actual security posture findings.
    """

    if not isinstance(finding, dict):
        return False

    finding_type = str(
        finding.get(
            "finding_type",
            ""
        )
    ).lower()

    finding_id = str(
        finding.get(
            "finding_id",
            ""
        )
    ).lower()

    issue = str(
        finding.get(
            "issue",
            ""
        )
    ).lower()

    return (
        finding_type == "cloudtrail"
        or finding_id.startswith(
            "cloudtrail-"
        )
        or "cloudtrail event" in issue
    )


class ScanService:
    """
    Main CloudGuardAI security scan orchestrator.

    Responsibilities:
    - Run all AWS security scanners
    - Separate security findings from CloudTrail activity
    - Calculate security posture
    - Generate AI security advice
    - Return a clean API response
    """

    def __init__(self):

        self.scanners = [
            S3Scanner(),
            IAMScanner(),
            EC2Scanner(),
            CloudTrailScanner(),
            ComplianceScanner(),
        ]

    def run_full_scan(self):

        print(
            "===== CloudGuardAI Full Scan ====="
        )

        # ====================================================
        # RUN ALL SCANNERS
        # ====================================================

        all_findings = []

        scanner_errors = []

        for scanner in self.scanners:

            scanner_name = (
                scanner.__class__.__name__
            )

            print(
                f"\nRunning {scanner_name}..."
            )

            try:

                scanner_findings = (
                    scanner.scan()
                )

                print(
                    f"{scanner_name} findings:",
                    len(scanner_findings),
                )

                all_findings.extend(
                    scanner_findings
                )

            except Exception as error:

                error_message = str(
                    error
                )

                print(
                    f"{scanner_name} failed:",
                    error_message,
                )

                scanner_errors.append(
                    {
                        "scanner":
                            scanner_name,

                        "error":
                            error_message,
                    }
                )

        # ====================================================
        # CONVERT ALL FINDINGS TO DICTIONARIES
        # ====================================================

        findings = [

            convert_finding_to_dict(
                finding
            )

            for finding in all_findings

        ]

        # ====================================================
        # SEPARATE SECURITY FINDINGS
        # FROM CLOUDTRAIL ACTIVITY
        # ====================================================

        security_findings = [

            finding

            for finding in findings

            if not is_cloudtrail_finding(
                finding
            )

        ]

        cloudtrail_events = [

            finding

            for finding in findings

            if is_cloudtrail_finding(
                finding
            )

        ]

        # ====================================================
        # CALCULATE SECURITY SCORE
        #
        # Score is based ONLY on real security findings.
        # CloudTrail activity does not reduce security score.
        # ====================================================

        score_result = (
            calculate_security_score(
                security_findings
            )
        )

        # ====================================================
        # GENERATE AI SECURITY ADVICE
        #
        # Advice is generated for real security findings only.
        # ====================================================

        print(
            "\nGenerating AI Security Advice..."
        )

        ai_advice = []

        for finding in security_findings:

            try:

                advice = (
                    generate_security_advice(
                        finding
                    )
                )

                ai_advice.append(
                    advice
                )

            except Exception as error:

                print(
                    "AI advice generation failed:",
                    str(error),
                )

        print(
            "AI Security Advice Generated:",
            len(ai_advice),
        )

        # ====================================================
        # BUILD CLEAN SUMMARY
        # ====================================================

        risk_summary = (
            score_result.get(
                "risk_summary",
                {}
            )
        )

        summary = {

            "total_security_findings":
                len(
                    security_findings
                ),

            "cloudtrail_events":
                len(
                    cloudtrail_events
                ),

            "total_items_analyzed":
                len(
                    findings
                ),

            "security_score":
                score_result.get(
                    "security_score",
                    0
                ),

            "security_grade":
                score_result.get(
                    "security_grade",
                    "F"
                ),

            "risk_summary": {

                "CRITICAL":
                    risk_summary.get(
                        "CRITICAL",
                        0
                    ),

                "HIGH":
                    risk_summary.get(
                        "HIGH",
                        0
                    ),

                "MEDIUM":
                    risk_summary.get(
                        "MEDIUM",
                        0
                    ),

                "LOW":
                    risk_summary.get(
                        "LOW",
                        0
                    ),

            },

        }

        # ====================================================
        # FINAL API RESULT
        # ====================================================

        result = {

            "project":
                "CloudGuardAI",

            "version":
                "3.0.0",

            "scan_status":
                "completed",

            "summary":
                summary,

            "security_findings":
                security_findings,

            "cloudtrail_events":
                cloudtrail_events,

            "ai_advice":
                ai_advice,

            "scanner_errors":
                scanner_errors,

        }

        # ====================================================
        # PRINT FINAL SUMMARY
        # ====================================================

        print(
            "\n===== FINAL CLOUDGUARD AI RESULT ====="
        )

        print(
            "Security Findings:",
            len(
                security_findings
            ),
        )

        print(
            "CloudTrail Events:",
            len(
                cloudtrail_events
            ),
        )

        print(
            "Total Items Analyzed:",
            len(
                findings
            ),
        )

        print(
            "Security Score:",
            summary[
                "security_score"
            ],
        )

        print(
            "Security Grade:",
            summary[
                "security_grade"
            ],
        )

        print(
            "Risk Summary:",
            summary[
                "risk_summary"
            ],
        )

        return result


def run_full_scan():
    """
    Backward-compatible wrapper.

    Existing API code can continue to call:

        run_full_scan()
    """

    scanner = ScanService()

    return scanner.run_full_scan()
