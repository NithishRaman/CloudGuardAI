from unittest.mock import MagicMock, patch

from backend.scanners.compliance_scanner import (
    ComplianceScanner,
)


@patch("backend.scanners.compliance_scanner.boto3.client")
def test_compliance_detects_user_without_mfa(mock_client):

    mock_iam = MagicMock()
    mock_cloudtrail = MagicMock()

    def client_factory(service_name, *args, **kwargs):
        if service_name == "iam":
            return mock_iam
        return mock_cloudtrail

    mock_client.side_effect = client_factory

    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "test-user"
            }
        ]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": []
    }

    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "security-trail"
            }
        ]
    }

    scanner = ComplianceScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].finding_type == "Compliance"

    assert findings[0].resource == "test-user"

    assert findings[0].risk == "HIGH"


@patch("backend.scanners.compliance_scanner.boto3.client")
def test_compliance_detects_missing_cloudtrail(mock_client):

    mock_iam = MagicMock()
    mock_cloudtrail = MagicMock()

    def client_factory(service_name, *args, **kwargs):
        if service_name == "iam":
            return mock_iam
        return mock_cloudtrail

    mock_client.side_effect = client_factory

    mock_iam.list_users.return_value = {
        "Users": []
    }

    mock_cloudtrail.describe_trails.return_value = {
        "trailList": []
    }

    scanner = ComplianceScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].finding_type == "Compliance"

    assert findings[0].risk == "CRITICAL"

    assert (
        findings[0].resource
        == "AWS Account"
    )


@patch("backend.scanners.compliance_scanner.boto3.client")
def test_compliance_passes_when_controls_exist(mock_client):

    mock_iam = MagicMock()
    mock_cloudtrail = MagicMock()

    def client_factory(service_name, *args, **kwargs):
        if service_name == "iam":
            return mock_iam
        return mock_cloudtrail

    mock_client.side_effect = client_factory

    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "secure-user"
            }
        ]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": [
            {
                "SerialNumber": "arn:aws:iam::123:mfa/secure-user"
            }
        ]
    }

    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "security-trail"
            }
        ]
    }

    scanner = ComplianceScanner()

    findings = scanner.scan()

    assert findings == []
