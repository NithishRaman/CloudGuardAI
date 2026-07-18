import boto3
import json

iam = boto3.client("iam")

findings = []

print("===== CloudGuardAI IAM Scanner =====")

response = iam.list_users()

users = response["Users"]

for user in users:

    username = user["UserName"]

    print("\nUser:", username)

    # MFA Check
    mfa = iam.list_mfa_devices(
        UserName=username
    )

    if len(mfa["MFADevices"]) > 0:

        print("MFA: Enabled")
        print("MFA Risk: LOW")
import boto3
import json

iam = boto3.client("iam")

findings = []

print("===== CloudGuardAI IAM Scanner =====")

response = iam.list_users()

users = response["Users"]

for user in users:

    username = user["UserName"]

    print("\nUser:", username)

    # MFA Check
    mfa = iam.list_mfa_devices(
        UserName=username
    )

    if len(mfa["MFADevices"]) > 0:

        print("MFA: Enabled")
        print("MFA Risk: LOW")

    else:

        print("MFA: Disabled")
        print("MFA Risk: HIGH")

        findings.append({
            "user": username,
            "issue": "MFA Disabled",
            "risk": "HIGH",
            "recommendation": "Enable MFA for this IAM user"
        })


    # Permission Check
    policies = iam.list_attached_user_policies(
        UserName=username
    )

    for policy in policies["AttachedPolicies"]:

        policy_name = policy["PolicyName"]

        print("Policy:", policy_name)

        if policy_name == "AdministratorAccess":

            print("Permission Risk: CRITICAL")

            findings.append({
                "user": username,
                "issue": "AdministratorAccess Policy",
                "risk": "CRITICAL",
                "recommendation": "Remove excessive admin permissions and follow least privilege"
            })

        else:

            print("Permission Risk: LOW")


    print("------------------------")


# Save IAM Security Report

with open("IAM_Security_Report.json", "w") as file:

    json.dump(findings, file, indent=4)


print("\nReport saved: IAM_Security_Report.json")

