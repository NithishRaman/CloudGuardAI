import json
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
    CloudGuardAI CloudTrail security scanner.
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

        event_id = event.get(
            "EventId",
            "unknown-event",
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

        elif event_name in LOW_RISK_EVENTS:

            risk = "LOW"

            reason = (
                "Low-risk AWS activity detected"
            )

        else:

            risk = "LOW"

            reason = (
                "AWS activity detected. "
                "Review if this activity "
                "was expected."
            )

        return SecurityFinding(

            finding_id=(
                f"CLOUDTRAIL-{event_id}"
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

            # CloudTrail returns CloudTrailEvent
            # as a JSON string containing
            # additional event information.

            cloudtrail_event = {}

            raw_event = event.get(
                "CloudTrailEvent"
            )

            if raw_event:

                try:

                    cloudtrail_event = json.loads(
                        raw_event
                    )

                except (
                    json.JSONDecodeError,
                    TypeError,
                ):

                    cloudtrail_event = {}

            # Merge useful identity information
            # into the event object.

            enriched_event = {
                **event,
                **cloudtrail_event,
            }

            finding = self.analyze_event(
                enriched_event
            )

            findings.append(
                finding
            )

        return findings
