from unittest.mock import MagicMock, patch

from backend.scanners.ec2_scanner import EC2Scanner


@patch("backend.scanners.ec2_scanner.boto3.client")
def test_ec2_scanner_detects_public_ip(
    mock_client,
):
    mock_ec2 = MagicMock()

    mock_client.return_value = mock_ec2

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1234567890",
                        "PublicIpAddress": "54.123.45.67",
                    }
                ]
            }
        ]
    }

    scanner = EC2Scanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].finding_type == "EC2"

    assert (
        findings[0].issue
        == "Public IP Exposed"
    )

    assert (
        findings[0].resource
        == "i-1234567890"
    )

    assert findings[0].risk == "MEDIUM"


@patch("backend.scanners.ec2_scanner.boto3.client")
def test_ec2_scanner_ignores_private_instance(
    mock_client,
):
    mock_ec2 = MagicMock()

    mock_client.return_value = mock_ec2

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-private123",
                    }
                ]
            }
        ]
    }

    scanner = EC2Scanner()

    findings = scanner.scan()

    assert findings == []


@patch("backend.scanners.ec2_scanner.boto3.client")
def test_ec2_scanner_handles_multiple_instances(
    mock_client,
):
    mock_ec2 = MagicMock()

    mock_client.return_value = mock_ec2

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-public123",
                        "PublicIpAddress": "1.2.3.4",
                    },
                    {
                        "InstanceId": "i-private123",
                    },
                ]
            }
        ]
    }

    scanner = EC2Scanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert (
        findings[0].resource
        == "i-public123"
    )
