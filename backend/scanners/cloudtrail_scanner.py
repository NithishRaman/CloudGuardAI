import boto3

from backend.models.finding import SecurityFinding


LOW_RISK_EVENTS = {
    "DescribeAlarms",
    "DescribeInstances",
    "ListBuckets",
    "CreateSession",
    "DeleteSession",
    "BackupJobCompleted",
    "RecoveryPointCreated",
    "PutCredentials",
}


MEDIUM_RISK_EVENTS = {
    "RunInstances",
    "StartInstances",
    "CreateTopic",
    "Subscribe",
}


HIGH_RISK_EVENTS = {
    "CreateAccessKey",
    "AssociateIamInstanceProfile",
    "ReplaceIamInstanceProfileAssociation",
    "AuthorizeSecurityGroupIngress",
}


CRITICAL_RISK_EVENTS = {
    "DeleteUser",
    "StopLogging",
    "DeleteTrail",
}


class CloudTrailScanner:
    """
    CloudGuardAI V2 CloudTrail security scanner.
    """

    def __init__(self):

        self.cloudtrail = boto3.client(
            "cloudtrail",
            region_name="ap-south-1",
        )

    def analyze_event(
        self,
        event: dict,
    ) -> SecurityFinding:

        event_name = event.get(
            "EventName",
            "Unknown",
        )

        user = event.get(
            "Username",
            "Unknown",
        )

        if user == "root":

            risk = "CRITICAL"

            reason = (
                "Root account activity detected"
            )

        elif event_name in CRITICAL_RISK_EVENTS:

            risk = "CRITICAL"

            reason = (
                "Critical security action detected"
            )

        elif event_name in HIGH_RISK_EVENTS:

            risk = "HIGH"

            reason = (
                "High risk IAM or network change"
            )

        elif event_name in MEDIUM_RISK_EVENTS:

            risk = "MEDIUM"

            reason = (
                "Moderate risk activity detected"
            )

        else:

            risk = "LOW"

            reason = "Normal activity"

        return SecurityFinding(

            finding_id=(
                f"CLOUDTRAIL-{event_name}-"
                f"{user}"
            ),

            finding_type="CloudTrail",

            issue=(
                f"AWS CloudTrail Event: "
                f"{event_name}"
            ),

            resource=user,

            risk=risk,

            description=reason,

            remediation=(
                "Review this CloudTrail event "
                "and verify that the activity "
                "was authorized."
            ),
        )

    def scan(
        self,
        max_results: int = 10,
    ) -> list[SecurityFinding]:

        findings = []

        response = (
            self.cloudtrail.lookup_events(
                MaxResults=max_results,
            )
        )

        events = response.get(
            "Events",
            [],
        )

        for event in events:

            finding = self.analyze_event(
                event
            )

            findings.append(finding)

        return findings

