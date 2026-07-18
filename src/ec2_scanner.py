import boto3
import json

ec2 = boto3.client(
    "ec2",
    region_name="ap-south-1"
)

findings = []

print("===== CloudGuardAI EC2 Scanner =====")


instances = ec2.describe_instances()


for reservation in instances["Reservations"]:

    for instance in reservation["Instances"]:

        instance_id = instance["InstanceId"]

        print("\nInstance:", instance_id)

        public_ip = instance.get("PublicIpAddress")


        if public_ip:

            print("Public IP:", public_ip)

            findings.append({
                "resource": instance_id,
                "issue": "Public IP exposed",
                "risk": "MEDIUM",
                "recommendation": "Review if public access is required"
            })

        else:

            print("Public IP: None")


        print("------------------------")


with open("EC2_Security_Report.json", "w") as file:

    json.dump(findings, file, indent=4)


print("\nReport saved: EC2_Security_Report.json")

