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
    Convert SecurityFinding dataclass into a dictionary.
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


class ScanService:
    """
    Main CloudGuardAI security scan orchestrator.
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

        all_findings = []
        scanner_errors = []

        # -----------------------------------------
        # Run all scanners
        # -----------------------------------------

        for scanner in self.scanners:

            scanner_name = (
                scanner.__class__.__name__
            )

            print(
                f"\nRunning {scanner_name}..."
            )

            try:

                scanner_findings = scanner.scan()

                print(
                    f"{scanner_name} findings:",
                    len(scanner_findings),
                )

                all_findings.extend(
                    scanner_findings
                )

            except Exception as error:

                error_message = str(error)

                print(
                    f"{scanner_name} failed:",
                    error_message,
                )

                scanner_errors.append(
                    {
                        "scanner": scanner_name,
                        "error": error_message,
                    }
                )

        # -----------------------------------------
        # Convert findings to dictionaries
        # -----------------------------------------

        findings = []

        for finding in all_findings:

            finding_dict = (
                convert_finding_to_dict(
                    finding
                )
            )

            findings.append(
                finding_dict
            )

        # -----------------------------------------
        # Calculate security score
        # -----------------------------------------

        score_result = (
            calculate_security_score(
                findings
            )
        )

        # -----------------------------------------
        # Generate AI security advice
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
            len(ai_advice),
        )

        # -----------------------------------------
        # Final result
        # -----------------------------------------

        result = {

            "project":
                "CloudGuardAI",

            "version":
                "3.0.0",

            "scan_status":
                "completed",

            "summary":
                score_result,

            "findings":
                findings,

            "ai_advice":
                ai_advice,

            "scanner_errors":
                scanner_errors,

        }

        # -----------------------------------------
        # Print summary
        # -----------------------------------------

        print(
            "\n===== FINAL CLOUDGUARD AI RESULT ====="
        )

        print(
            "Total Findings:",
            score_result[
                "total_findings"
            ],
        )

        print(
            "Security Score:",
            score_result[
                "security_score"
            ],
        )

        print(
            "Security Grade:",
            score_result[
                "security_grade"
            ],
        )

        print(
            "Risk Summary:",
            score_result[
                "risk_summary"
            ],
        )

        return result


def run_full_scan():
    """
    Backward-compatible wrapper.

    Allows existing API code to call:

        run_full_scan()
    """

    scanner = ScanService()

    return scanner.run_full_scan()
