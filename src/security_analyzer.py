LOW_RISK_EVENTS = [
    "DescribeAlarms",
    "DescribeInstances",
    "ListBuckets",
    "CreateSession",
    "DeleteSession",
    "BackupJobCompleted",
    "RecoveryPointCreated",
    "PutCredentials"
]


MEDIUM_RISK_EVENTS = [
    "RunInstances",
    "StartInstances",
    "CreateTopic",
    "Subscribe"
]


HIGH_RISK_EVENTS = [
    "CreateAccessKey",
    "AssociateIamInstanceProfile",
    "ReplaceIamInstanceProfileAssociation",
    "AuthorizeSecurityGroupIngress"
]


CRITICAL_RISK_EVENTS = [
    "DeleteUser",
    "StopLogging",
    "DeleteTrail"
]


def analyze_event(event):

    event_name = event.get(
        "EventName",
        "Unknown"
    )


    user = "Unknown"


    if "Username" in event:
        user = event["Username"]


    if user == "root":

        return {

            "event": event_name,

            "user": user,

            "risk": "CRITICAL",

            "reason": "Root account activity detected"

        }


    elif event_name in CRITICAL_RISK_EVENTS:

        return {

            "event": event_name,

            "user": user,

            "risk": "CRITICAL",

            "reason": "Critical security action detected"

        }


    elif event_name in HIGH_RISK_EVENTS:

        return {

            "event": event_name,

            "user": user,

            "risk": "HIGH",

            "reason": "High risk IAM or network change"

        }


    elif event_name in MEDIUM_RISK_EVENTS:

        return {

            "event": event_name,

            "user": user,

            "risk": "MEDIUM",

            "reason": "Moderate risk activity detected"

        }


    else:

        return {

            "event": event_name,

            "user": user,

            "risk": "LOW",

            "reason": "Normal activity"

        }
