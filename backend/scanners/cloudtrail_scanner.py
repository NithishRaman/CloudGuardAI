import json
import boto3

from backend.models.finding import SecurityFinding


# Low-risk CloudTrail events
LOW_RISK_EVENTS = {
    "DescribeAlarms",
    "DescribeInstances",
    "ListBuckets",
    "CreateSession",
    "DeleteSession",
    "BackupJobCompleted",
    "RecoveryPointCreated",
    "PutCredentials",
    "DescribeTrails",
    "LookupEvents",
    "GetBucketPublicAccessBlock",
    "GetBucketAcl",
    "DescribeACLs",
    "GetSamplingRules",
}


# Medium-risk CloudTrail events
MEDIUM_RISK_EVENTS = {
    "RunInstances",
    "StartInstances",
    "CreateTopic",
    "Subscribe",
}


# High-risk CloudTrail events
HIGH_RISK_EVENTS = {
    "CreateAccessKey",
    "DeleteAccessKey",
    "DeleteLoginProfile",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "DetachUserPolicy",
    "DetachRolePolicy",
    "DetachGroupPolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeactivateMFADevice",
    "AssociateIamInstanceProfile",
    "ReplaceIamInstanceProfileAssociation",
    "AuthorizeSecurityGroupIngress",
}


# Critical-risk CloudTrail events
CRITICAL_RISK_EVENTS = {
    "DeleteUser",
    "StopLogging",
    "DeleteTrail",
}


class CloudTrailScanner:
    """
    CloudGuardAI CloudTrail security scanner.

    Analyzes AWS CloudTrail events and assigns
    a security risk level.
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

        # -----------------------------------------
        # Risk classification
        # -----------------------------------------

        # Root activity is always critical.
        if user == "root":

            risk = "CRITICAL"

            reason = (
                "Root account activity detected. "
                "Investigate this activity immediately."
            )

        # Critical security actions
        elif event_name in CRITICAL_RISK_EVENTS:

            risk = "CRITICAL"

            reason = (
                "Critical security-sensitive AWS "
                "activity detected."
            )

        # High-risk security actions
        elif event_name in HIGH_RISK_EVENTS:

            risk = "HIGH"

            reason = (
                "High-risk IAM or security "
                "configuration activity detected."
            )

        # Medium-risk security actions
        elif event_name in MEDIUM_RISK_EVENTS:

            risk = "MEDIUM"

            reason = (
                "Security-sensitive AWS activity "
                "detected."
            )

        # Known low-risk activity
        elif event_name in LOW_RISK_EVENTS:

            risk = "LOW"

            reason = (
                "Low-risk AWS activity detected. "
                "Review if this activity was expected."
            )

        # Unknown events are also recorded as LOW
        # so that CloudGuardAI does not silently
        # ignore CloudTrail activity.
        else:

            risk = "LOW"

            reason = (
                "AWS activity detected. "
                "Review if this activity was expected."
            )

        # -----------------------------------------
        # Create security finding
        # -----------------------------------------

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
                "Review the CloudTrail event and "
                "verify that the activity was "
                "authorized."
            ),
        )

    def scan(
        self,
        max_results: int = 50,
    ) -> list[SecurityFinding]:

        findings = []

        # -----------------------------------------
        # Get CloudTrail events
        # -----------------------------------------

        response = (
            self.cloudtrail.lookup_events(
                MaxResults=max_results,
            )
        )

        events = response.get(
            "Events",
            [],
        )

        # -----------------------------------------
        # Process events
        # -----------------------------------------

        for event in events:

            cloudtrail_event = {}

            raw_event = event.get(
                "CloudTrailEvent"
            )

            # CloudTrailEvent is usually
            # returned as a JSON string.
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

            # Merge the original event with
            # detailed CloudTrail event data.
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

        # -----------------------------------------
        # Remove duplicate findings
        # -----------------------------------------

        unique_findings = {}

        for finding in findings:
             
             # Use the finding ID as the unique key.
            key = finding.finding_id


            if key not in unique_findings:

                unique_findings[key] = finding

        return list(
            unique_findings.values()
        )
