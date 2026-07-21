from backend.scanners.ec2_scanner import EC2Scanner


def main():

    print(
        "===== CloudGuardAI V2 EC2 Scanner ====="
    )

    scanner = EC2Scanner()

    findings = scanner.scan()

    print(
        f"\nTotal EC2 findings: {len(findings)}"
    )

    if not findings:

        print(
            "No EC2 security findings detected."
        )

    for finding in findings:

        print("\nFinding:")

        print(
            "ID:",
            finding.finding_id
        )

        print(
            "Type:",
            finding.finding_type
        )

        print(
            "Issue:",
            finding.issue
        )

        print(
            "Resource:",
            finding.resource
        )

        print(
            "Risk:",
            finding.risk
        )

        print(
            "Description:",
            finding.description
        )

        print(
            "Remediation:",
            finding.remediation
        )


if __name__ == "__main__":
    main()
