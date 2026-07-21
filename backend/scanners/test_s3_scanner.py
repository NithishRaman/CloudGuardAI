from backend.scanners.s3_scanner import S3Scanner


def main():

    print("===== CloudGuardAI V2 S3 Scanner =====")

    scanner = S3Scanner()

    findings = scanner.scan()

    print(
        f"\nTotal S3 findings: {len(findings)}"
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
