import json
from datetime import datetime


print("===== CloudGuardAI Security Engine =====")


final_findings = []


# -----------------------------
# Load CloudTrail Report
# -----------------------------

try:

    with open("CloudGuardAI_Report.json", "r") as file:

        cloudtrail_report = json.load(file)

        for finding in cloudtrail_report["findings"]:

            finding["type"] = "CloudTrail"

            final_findings.append(finding)


except FileNotFoundError:

    print("CloudTrail report not found")



# -----------------------------
# Load IAM Report
# -----------------------------

try:

    with open("IAM_Security_Report.json", "r") as file:

        iam_report = json.load(file)

        for finding in iam_report:

            finding["type"] = "IAM"

            final_findings.append(finding)


except FileNotFoundError:

    print("IAM report not found")



# -----------------------------
# Load EC2 Report
# -----------------------------

try:

    with open("EC2_Security_Report.json", "r") as file:

        ec2_report = json.load(file)

        for finding in ec2_report:

            finding["type"] = "EC2"

            final_findings.append(finding)


except FileNotFoundError:

    print("EC2 report not found")



# -----------------------------
# Load S3 Report
# -----------------------------

try:

    with open("S3_Security_Report.json", "r") as file:

        s3_report = json.load(file)

        for finding in s3_report:

            finding["type"] = "S3"

            final_findings.append(finding)


except FileNotFoundError:

    print("S3 report not found")



# -----------------------------
# Load Compliance Report
# -----------------------------

try:

    with open("Compliance_Report.json", "r") as file:

        compliance_report = json.load(file)


        for finding in compliance_report:

            final_findings.append({

                "type": "Compliance",

                "issue": finding.get("check"),

                "resource": finding.get("resource", "AWS"),

                "status": finding.get("status"),

                "risk": finding.get("risk")

            })


except FileNotFoundError:

    print("Compliance report not found")



# -----------------------------
# Risk Summary
# -----------------------------

risk_summary = {

    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0

}



for finding in final_findings:

    risk = finding.get("risk")


    if risk in risk_summary:

        risk_summary[risk] += 1



# -----------------------------
# Security Score
# -----------------------------

security_score = 100


unique_findings = set()



for finding in final_findings:

    name = (

        finding.get("issue")
        or finding.get("event")
        or finding.get("check")

    )

    risk = finding.get("risk")


    unique_findings.add(
        (name, risk)
    )



for item in unique_findings:

    risk = item[1]


    if risk == "CRITICAL":

        security_score -= 15


    elif risk == "HIGH":

        security_score -= 8


    elif risk == "MEDIUM":

        security_score -= 3


    elif risk == "LOW":

        security_score -= 1



if security_score < 0:

    security_score = 0



# -----------------------------
# Security Grade
# -----------------------------

if security_score >= 90:

    grade = "A"


elif security_score >= 75:

    grade = "B"


elif security_score >= 50:

    grade = "C"


elif security_score >= 25:

    grade = "D"


else:

    grade = "F"



# -----------------------------
# Final Report
# -----------------------------

final_report = {

    "project": "CloudGuardAI",

    "generated_time": str(datetime.now()),

    "security_score": security_score,

    "security_grade": grade,

    "risk_summary": risk_summary,

    "total_findings": len(final_findings),

    "findings": final_findings

}



with open(
    "FINAL_CLOUDGUARD_AI_REPORT.json",
    "w"
) as file:

    json.dump(
        final_report,
        file,
        indent=4
    )



print("\nFinal CloudGuardAI Report Generated")

print("Total Findings:", len(final_findings))

print("Security Score:", security_score, "/100")

print("Security Grade:", grade)

print("Risk Summary:", risk_summary)

print("Saved: FINAL_CLOUDGUARD_AI_REPORT.json")





