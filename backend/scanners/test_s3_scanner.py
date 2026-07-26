from unittest.mock import MagicMock, patch

from backend.scanners.s3_scanner import S3Scanner


@patch("backend.scanners.s3_scanner.boto3.client")
def test_s3_scanner_detects_missing_public_access_block(
    mock_client,
):
    mock_s3 = MagicMock()

    mock_client.return_value = mock_s3

    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "test-bucket",
            }
        ]
    }

    mock_s3.exceptions.NoSuchPublicAccessBlockConfiguration = (
        type(
            "NoSuchPublicAccessBlockConfiguration",
            (Exception,),
            {},
        )
    )

    mock_s3.get_public_access_block.side_effect = (
        mock_s3.exceptions.NoSuchPublicAccessBlockConfiguration()
    )

    scanner = S3Scanner()

    findings = scanner.scan()

    assert len(findings) == 1

    assert findings[0].finding_type == "S3"

    assert (
        findings[0].issue
        == "S3 Public Access Block Disabled"
    )

    assert findings[0].resource == "test-bucket"

    assert findings[0].risk == "CRITICAL"


@patch("backend.scanners.s3_scanner.boto3.client")
def test_s3_scanner_returns_no_findings_when_protected(
    mock_client,
):
    mock_s3 = MagicMock()

    mock_client.return_value = mock_s3

    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "secure-bucket",
            }
        ]
    }

    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    scanner = S3Scanner()

    findings = scanner.scan()

    assert findings == []
