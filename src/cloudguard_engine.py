import json
from datetime import datetime
from remediation_engine import generate_fix


print("===== CloudGuardAI Security Engine =====")


final_findings = []


def load_report(filename, finding_type):
    try:
        with open(filename, "r") as file:
            report = json.load(file)

            for finding in report:
                finding["type"] = finding_type
                final_findings.append(finding)

    except FileNotFoundError:
        print(f"{filename} not found")


# -----------------------------
# Load CloudTrail Report
# -----------------------------

try:
    with open("CloudGuardAI_Report.json", "r") as file:

        cloudtrail_report = json.load(file)

        for finding in cloudtrail_report.get("findings", []):

            finding["type"] = "CloudTrail"

            final_findings.append(finding)

except FileNotFoundError:
    print("CloudTrail report not found")


# -----------------------------
# Load IAM Report
# -----------------------------

load_report(
    "IAM_Security_Report.json",
    "IAM"
)


# -----------------------------
# Load EC2 Report
# -----------------------------

load_report(
    "EC2_Security_Report.json",
    "EC2"
)


# -----------------------------
# Load S3 Report
# -----------------------------

load_report(
    "S3_Security_Report.json",
    "S3"
)


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

                "details": finding.get("details")

            })


except FileNotFoundError:

    print("Compliance report not found")


# -----------------------------
# Add Remediation
# -----------------------------

for finding in final_findings:

    finding["remediation"] = generate_fix(finding)



# -----------------------------
# Risk Analysis
# -----------------------------

risk_summary = {

    "Critical": 0,

    "High": 0,

    "Medium": 0,

    "Low": 0

}


for finding in final_findings:

    severity = finding.get(
        "severity",
        "Medium"
    )

    if severity in risk_summary:

        risk_summary[severity] += 1



# -----------------------------
# Security Score
# -----------------------------

security_score = 100


for finding in final_findings:

    severity = finding.get(
        "severity",
        "Medium"
    )


    if severity == "Critical":

        security_score -= 20


    elif severity == "High":

        security_score -= 10


    elif severity == "Medium":

        security_score -= 5


    elif severity == "Low":

        security_score -= 2



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

