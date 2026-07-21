from backend.services.scan_service import (
    ScanService,
)


def main():

    scanner = ScanService()

    result = scanner.run_full_scan()

    print("\n===== FINAL CLOUDGUARD AI RESULT =====")

    print(
        "Total Findings:",
        result["total_findings"]
    )

    print(
        "Security Score:",
        result["security_score"]
    )

    print(
        "Security Grade:",
        result["security_grade"]
    )

    print(
        "Risk Summary:",
        result["risk_summary"]
    )


if __name__ == "__main__":

    main()
