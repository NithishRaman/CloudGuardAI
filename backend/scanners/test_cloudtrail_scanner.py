from unittest.mock import MagicMock, patch

from backend.scanners.cloudtrail_scanner import (
    CloudTrailScanner,
)


@patch("backend.scanners.cloudtrail_scanner.boto3.client")
def test_root_activity_is_critical(mock_client):

    mock_cloudtrail = MagicMock()

    mock_client.return_value = mock_cloudtrail

    mock_cloudtrail.lookup_events.return_value = {
        "Events": [
            {
                "EventName": "DescribeInstances",
                "Username": "root",
            }
        ]
    }

    scanner = CloudTrailScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].risk == "CRITICAL"

    assert findings[0].resource == "root"


@patch("backend.scanners.cloudtrail_scanner.boto3.client")
def test_critical_event_detected(mock_client):

    mock_cloudtrail = MagicMock()

    mock_client.return_value = mock_cloudtrail

    mock_cloudtrail.lookup_events.return_value = {
        "Events": [
            {
                "EventName": "DeleteTrail",
                "Username": "admin",
            }
        ]
    }

    scanner = CloudTrailScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].risk == "CRITICAL"

    assert (
        findings[0].issue
        == "AWS CloudTrail Event: DeleteTrail"
    )


@patch("backend.scanners.cloudtrail_scanner.boto3.client")
def test_high_risk_event_detected(mock_client):

    mock_cloudtrail = MagicMock()

    mock_client.return_value = mock_cloudtrail

    mock_cloudtrail.lookup_events.return_value = {
        "Events": [
            {
                "EventName": "CreateAccessKey",
                "Username": "admin",
            }
        ]
    }

    scanner = CloudTrailScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].risk == "HIGH"


@patch("backend.scanners.cloudtrail_scanner.boto3.client")
def test_medium_risk_event_detected(mock_client):

    mock_cloudtrail = MagicMock()

    mock_client.return_value = mock_cloudtrail

    mock_cloudtrail.lookup_events.return_value = {
        "Events": [
            {
                "EventName": "RunInstances",
                "Username": "developer",
            }
        ]
    }

    scanner = CloudTrailScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].risk == "MEDIUM"


@patch("backend.scanners.cloudtrail_scanner.boto3.client")
def test_normal_event_is_low_risk(mock_client):

    mock_cloudtrail = MagicMock()

    mock_client.return_value = mock_cloudtrail

    mock_cloudtrail.lookup_events.return_value = {
        "Events": [
            {
                "EventName": "DescribeInstances",
                "Username": "developer",
            }
        ]
    }

    scanner = CloudTrailScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].risk == "LOW"


@patch("backend.scanners.cloudtrail_scanner.boto3.client")
def test_empty_cloudtrail_returns_no_findings(mock_client):

    mock_cloudtrail = MagicMock()

    mock_client.return_value = mock_cloudtrail

    mock_cloudtrail.lookup_events.return_value = {
        "Events": []
    }

    scanner = CloudTrailScanner()

    findings = scanner.scan()

    assert findings == []
