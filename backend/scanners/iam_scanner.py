import boto3

from backend.models.finding import SecurityFinding


class IAMScanner:
    """
    CloudGuardAI V2 IAM security scanner.
    """

    def __init__(self):
        self.iam = boto3.client("iam")

    def scan(self) -> list[SecurityFinding]:
        """
        Scan IAM users for security risks.
        """

        findings = []

        response = self.iam.list_users()

        users = response.get("Users", [])

        for user in users:

            username = user["UserName"]

            # -----------------------------
            # MFA Check
            # -----------------------------

            mfa_response = self.iam.list_mfa_devices(
                UserName=username
            )

            mfa_devices = mfa_response.get(
                "MFADevices",
                []
            )

            if not mfa_devices:

                findings.append(
                    SecurityFinding(
                        finding_id=f"IAM-MFA-{username}",
                        finding_type="IAM",
                        issue="MFA Disabled",
                        resource=username,
                        risk="HIGH",
                        description=(
                            "MFA is not enabled "
                            "for this IAM user."
                        ),
                        remediation=(
                            "Enable MFA for this IAM user."
                        ),
                    )
                )

            # -----------------------------
            # Attached Policy Check
            # -----------------------------

            policies_response = (
                self.iam.list_attached_user_policies(
                    UserName=username
                )
            )

            policies = policies_response.get(
                "AttachedPolicies",
                []
            )

            for policy in policies:

                policy_name = policy["PolicyName"]

                if policy_name == "AdministratorAccess":

                    findings.append(
                        SecurityFinding(
                            finding_id=(
                                f"IAM-ADMIN-{username}"
                            ),
                            finding_type="IAM",
                            issue=(
                                "AdministratorAccess "
                                "Policy"
                            ),
                            resource=username,
                            risk="CRITICAL",
                            description=(
                                "This IAM user has "
                                "full administrative "
                                "permissions."
                            ),
                            remediation=(
                                "Remove excessive "
                                "administrator permissions "
                                "and follow the principle "
                                "of least privilege."
                            ),
                        )
                    )

        return findings
