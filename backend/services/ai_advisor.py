from typing import Dict


def generate_security_advice(
    finding: Dict
) -> Dict:

    risk = finding.get(
        "risk",
        "UNKNOWN"
    )

    issue = finding.get(
        "issue",
        "Unknown security issue"
    )

    resource = finding.get(
        "resource",
        "Unknown resource"
    )


    # -----------------------------
    # Critical Risk
    # -----------------------------

    if risk == "CRITICAL":

        analysis = (
            f"The resource '{resource}' has a critical security issue: "
            f"{issue}. This configuration may provide excessive privileges "
            "or create a significant security exposure."
        )

        priority = "IMMEDIATE"

        action = (
            "Investigate this finding immediately and apply the recommended "
            "least-privilege or security control."
        )


    # -----------------------------
    # High Risk
    # -----------------------------

    elif risk == "HIGH":

        analysis = (
            f"The resource '{resource}' has a high-risk security issue: "
            f"{issue}. This configuration increases the likelihood of "
            "unauthorized access or account compromise."
        )

        priority = "HIGH"

        action = (
            "Address this finding as soon as possible and verify that "
            "appropriate security controls are enabled."
        )


    # -----------------------------
    # Medium Risk
    # -----------------------------

    elif risk == "MEDIUM":

        analysis = (
            f"The resource '{resource}' has a medium-risk issue: "
            f"{issue}. This may increase the attack surface of the AWS "
            "environment."
        )

        priority = "MEDIUM"

        action = (
            "Review the configuration and apply the recommended security "
            "improvements."
        )


    # -----------------------------
    # Low Risk
    # -----------------------------

    else:

        analysis = (
            f"The resource '{resource}' generated a low-risk security "
            f"finding related to {issue}. This does not appear to be an "
            "immediate security threat."
        )

        priority = "LOW"

        action = (
            "Review the activity and verify that it was authorized."
        )


    return {

        "finding_id": finding.get(
            "finding_id"
        ),

        "risk": risk,

        "priority": priority,

        "analysis": analysis,

        "recommended_action": action

    }
