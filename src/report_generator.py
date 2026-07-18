from datetime import datetime
import json


def generate_report(results):

    report = {
        "project": "CloudGuardAI",
        "generated_time": str(datetime.now()),
        "findings": results
    }

    with open("CloudGuardAI_Report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("\n===== CloudGuardAI Security Report =====")
    print("Generated:", datetime.now())
    print("----------------------------------------")

    for result in results:
        print("\nEvent:", result["event"])
        print("User:", result["user"])
        print("Risk:", result["risk"])
        print("Reason:", result["reason"])
        print("----------------------------------------")

    print("\nReport saved: CloudGuardAI_Report.json")


