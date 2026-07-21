import boto3

from backend.models.finding import SecurityFinding


class EC2Scanner:
    """
    CloudGuardAI V2 EC2 security scanner.
    """

    def __init__(self):
        self.ec2 = boto3.client(
            "ec2",
            region_name="ap-south-1"
        )

    def scan(self) -> list[SecurityFinding]:
        """
        Scan EC2 instances for public IP exposure.
        """

        findings = []

        response = self.ec2.describe_instances()

        for reservation in response.get(
            "Reservations",
            []
        ):

            for instance in reservation.get(
                "Instances",
                []
            ):

                instance_id = instance[
                    "InstanceId"
                ]

                public_ip = instance.get(
                    "PublicIpAddress"
                )

                if public_ip:

                    findings.append(
                        SecurityFinding(
                            finding_id=(
                                f"EC2-PUBLIC-IP-"
                                f"{instance_id}"
                            ),
                            finding_type="EC2",
                            issue="Public IP Exposed",
                            resource=instance_id,
                            risk="MEDIUM",
                            description=(
                                f"EC2 instance has "
                                f"public IP address "
                                f"{public_ip}."
                            ),
                            remediation=(
                                "Review whether public "
                                "internet access is "
                                "required. If not, remove "
                                "the public IP and use "
                                "private networking."
                            ),
                        )
                    )

        return findings
