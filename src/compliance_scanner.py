import boto3
import json


iam = boto3.client("iam")
cloudtrail = boto3.client(
    "cloudtrail",
    region_name="ap-south-1"
)


checks = []


print("===== CloudGuardAI Compliance Scanner =====")


# IAM Users MFA Check

users = iam.list_users()


for user in users["Users"]:

    username = user["UserName"]

    mfa = iam.list_mfa_devices(
        UserName=username
    )


    if len(mfa["MFADevices"]) == 0:

        checks.append({

            "check": "IAM MFA Enabled",

            "resource": username,

            "status": "FAIL",

            "risk": "HIGH"

        })

    else:

        checks.append({

            "check": "IAM MFA Enabled",

            "resource": username,

            "status": "PASS",

            "risk": "LOW"

        })



# CloudTrail Check

trails = cloudtrail.describe_trails()


if len(trails["trailList"]) > 0:

    checks.append({

        "check": "CloudTrail Enabled",

        "status": "PASS",

        "risk": "LOW"

    })

else:

    checks.append({

        "check": "CloudTrail Enabled",

        "status": "FAIL",

        "risk": "CRITICAL"

    })



with open(
    "Compliance_Report.json",
    "w"
) as file:

    json.dump(
        checks,
        file,
        indent=4
    )


print("Compliance Report Saved")


