from backend.scanners.iam_scanner import IAMScanner


def main():

    print("===== CloudGuardAI V2 IAM Scanner =====")

    scanner = IAMScanner()

    findings = scanner.scan()

    print(
        f"\nTotal IAM findings: {len(findings)}"
    )

    for finding in findings:

        print("\nFinding:")

        print("ID:", finding.finding_id)

        print("Type:", finding.finding_type)

        print("Issue:", finding.issue)

        print("Resource:", finding.resource)

        print("Risk:", finding.risk)

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
