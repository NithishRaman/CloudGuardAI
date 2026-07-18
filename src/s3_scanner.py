import boto3
import json

s3 = boto3.client("s3")

findings = []

print("===== CloudGuardAI S3 Scanner =====")


buckets = s3.list_buckets()


for bucket in buckets["Buckets"]:

    name = bucket["Name"]

    print("\nBucket:", name)


    try:

        public_access = s3.get_public_access_block(
            Bucket=name
        )

        print("Public Access Block: Enabled")

    except:

        print("Public Access Block: Missing")

        findings.append({
            "resource": name,
            "issue": "S3 Public Access Block Disabled",
            "risk": "CRITICAL",
            "recommendation": "Enable S3 Block Public Access"
        })


    print("------------------------")


with open("S3_Security_Report.json","w") as file:

    json.dump(findings,file,indent=4)


print("\nReport saved: S3_Security_Report.json")

