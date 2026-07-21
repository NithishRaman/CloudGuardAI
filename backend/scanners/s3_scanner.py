import boto3

from backend.models.finding import SecurityFinding


class S3Scanner:
    """
    CloudGuardAI V2 S3 security scanner.
    """

    def __init__(self):
        self.s3 = boto3.client("s3")

    def scan(self) -> list[SecurityFinding]:
        """
        Scan all S3 buckets for security issues.
        """

        findings = []

        response = self.s3.list_buckets()

        for bucket in response.get("Buckets", []):

            bucket_name = bucket["Name"]

            try:
                self.s3.get_public_access_block(
                    Bucket=bucket_name
                )

            except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:

                findings.append(
                    SecurityFinding(
                        finding_id=f"S3-PAB-{bucket_name}",
                        finding_type="S3",
                        issue="S3 Public Access Block Disabled",
                        resource=bucket_name,
                        risk="CRITICAL",
                        description=(
                            "The S3 bucket does not have "
                            "Public Access Block enabled."
                        ),
                        remediation=(
                            "Enable S3 Block Public Access "
                            "for this bucket."
                        ),
                    )
                )

        return findings
