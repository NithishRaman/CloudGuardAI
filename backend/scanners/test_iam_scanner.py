from unittest.mock import MagicMock, patch

from backend.scanners.iam_scanner import IAMScanner


@patch("backend.scanners.iam_scanner.boto3.client")
def test_iam_scanner_detects_missing_mfa(
    mock_client,
):
    mock_iam = MagicMock()

    mock_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "test-user",
            }
        ]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": []
    }

    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": []
    }

    scanner = IAMScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].finding_type == "IAM"

    assert findings[0].issue == "MFA Disabled"

    assert findings[0].resource == "test-user"

    assert findings[0].risk == "HIGH"


@patch("backend.scanners.iam_scanner.boto3.client")
def test_iam_scanner_detects_administrator_access(
    mock_client,
):
    mock_iam = MagicMock()

    mock_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "admin-user",
            }
        ]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": [
            {
                "SerialNumber": "arn:aws:iam::123:mfa/test"
            }
        ]
    }

    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
            }
        ]
    }

    scanner = IAMScanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert (
        findings[0].issue
        == "AdministratorAccess Policy"
    )

    assert (
        findings[0].resource
        == "admin-user"
    )

    assert (
        findings[0].risk
        == "CRITICAL"
    )


@patch("backend.scanners.iam_scanner.boto3.client")
def test_iam_scanner_detects_multiple_risks(
    mock_client,
):
    mock_iam = MagicMock()

    mock_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "risky-user",
            }
        ]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": []
    }

    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
            }
        ]
    }

    scanner = IAMScanner()

    findings = scanner.scan()

    assert len(findings) == 2

    issues = {
        finding.issue
        for finding in findings
    }

    assert "MFA Disabled" in issues

    assert (
        "AdministratorAccess Policy"
        in issues
    )
