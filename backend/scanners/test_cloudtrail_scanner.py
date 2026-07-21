from backend.scanners.cloudtrail_scanner import (
    CloudTrailScanner,
)


def main():

    print(
        "===== CloudGuardAI V2 CloudTrail Scanner ====="
    )

    scanner = CloudTrailScanner()

    findings = scanner.scan(
        max_results=10
    )

    print(
        f"\nTotal CloudTrail findings: "
        f"{len(findings)}"
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
