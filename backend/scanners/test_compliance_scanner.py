from backend.scanners.compliance_scanner import (
    ComplianceScanner,
)


def main():

    print(
        "===== CloudGuardAI V2 Compliance Scanner ====="
    )

    scanner = ComplianceScanner()

    findings = scanner.scan()

    print(
        f"\nTotal Compliance findings: "
        f"{len(findings)}"
    )

    if not findings:

        print(
            "No compliance issues detected."
        )

    for finding in findings:

        print("\nFinding:")

        print(
            "ID:",
            finding.finding_id,
        )

        print(
            "Type:",
            finding.finding_type,
        )

        print(
            "Issue:",
            finding.issue,
        )

        print(
            "Resource:",
            finding.resource,
        )

        print(
            "Risk:",
            finding.risk,
        )

        print(
            "Description:",
            finding.description,
        )

        print(
            "Remediation:",
            finding.remediation,
        )


if __name__ == "__main__":

    main()
