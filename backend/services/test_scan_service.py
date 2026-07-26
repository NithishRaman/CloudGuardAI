from unittest.mock import patch

from backend.services.scan_service import (
    ScanService,
)


def test_scan_service_initializes():

    scanner = ScanService()

    assert scanner is not None

    assert len(
        scanner.scanners
    ) == 5


@patch(
    "backend.services.scan_service.generate_security_advice"
)
def test_scan_service_runs_scan(
    mock_ai_advice,
):

    mock_ai_advice.return_value = {
        "finding_id": "TEST-001",
        "risk": "HIGH",
        "priority": "HIGH",
        "analysis": "Test analysis",
        "recommended_action": "Test action",
    }

    scanner = ScanService()

    fake_findings = []

    for scan in scanner.scanners:

        scan.scan = lambda: []

    result = scanner.run_full_scan()

    assert result["project"] == "CloudGuardAI"

    assert result["scan_status"] == "completed"

    assert result["summary"]["total_findings"] == 0

    assert result["summary"]["security_score"] == 100

    assert result["summary"]["security_grade"] == "A"

    assert result["findings"] == []

    assert result["ai_advice"] == []
