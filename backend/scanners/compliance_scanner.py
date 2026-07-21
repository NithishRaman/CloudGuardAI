import boto3

from backend.models.finding import SecurityFinding


class ComplianceScanner:
    """
    CloudGuardAI V2 compliance scanner.
    """

    def __init__(self):

        self.iam = boto3.client(
            "iam"
        )

        self.cloudtrail = boto3.client(
            "cloudtrail",
            region_name="ap-south-1"
        )

    def scan(self) -> list[SecurityFinding]:

        findings = []

        # -----------------------------
        # IAM MFA Compliance Check
        # -----------------------------

        users_response = (
            self.iam.list_users()
        )

        users = users_response.get(
            "Users",
            []
        )

        for user in users:

            username = user[
                "UserName"
            ]

            mfa_response = (
                self.iam.list_mfa_devices(
                    UserName=username
                )
            )

            mfa_devices = (
                mfa_response.get(
                    "MFADevices",
                    []
                )
            )

            if not mfa_devices:

                findings.append(
                    SecurityFinding(
                        finding_id=(
                            f"COMPLIANCE-MFA-"
                            f"{username}"
                        ),
                        finding_type=(
                            "Compliance"
                        ),
                        issue=(
                            "IAM MFA Enabled"
                        ),
                        resource=username,
                        risk="HIGH",
                        description=(
                            "IAM user does not "
                            "have MFA enabled."
                        ),
                        remediation=(
                            "Enable MFA for "
                            "this IAM user."
                        ),
                    )
                )

        # -----------------------------
        # CloudTrail Compliance Check
        # -----------------------------

        trails_response = (
            self.cloudtrail.describe_trails()
        )

        trails = trails_response.get(
            "trailList",
            []
        )

        if not trails:

            findings.append(
                SecurityFinding(
                    finding_id=(
                        "COMPLIANCE-CLOUDTRAIL"
                    ),
                    finding_type=(
                        "Compliance"
                    ),
                    issue=(
                        "CloudTrail Enabled"
                    ),
                    resource="AWS Account",
                    risk="CRITICAL",
                    description=(
                        "No CloudTrail trail "
                        "was detected."
                    ),
                    remediation=(
                        "Create and enable "
                        "an AWS CloudTrail trail "
                        "for security monitoring."
                    ),
                )
            )

        return findings
