from backend.services.ai_advisor import generate_security_advice


test_finding = {

    "finding_id": "IAM-ADMIN-Nithish",

    "finding_type": "IAM",

    "issue": "AdministratorAccess Policy",

    "resource": "Nithish",

    "risk": "CRITICAL",

    "description": (
        "This IAM user has full administrative permissions."
    ),

    "remediation": (
        "Remove excessive administrator permissions "
        "and follow the principle of least privilege."
    )

}


advice = generate_security_advice(
    test_finding
)


print("\n===== CloudGuardAI AI Security Advisor =====")

print(
    "Finding:",
    advice["finding_id"]
)

print(
    "Risk:",
    advice["risk"]
)

print(
    "Priority:",
    advice["priority"]
)

print(
    "\nAI Analysis:"
)

print(
    advice["analysis"]
)

print(
    "\nRecommended Action:"
)

print(
    advice["recommended_action"]
)
