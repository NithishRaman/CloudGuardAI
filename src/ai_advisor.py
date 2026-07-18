def generate_advice(finding):

    risk = finding.get("risk", "LOW")

    issue = (
        finding.get("issue")
        or finding.get("event")
        or "Unknown Security Event"
    )


    if risk == "CRITICAL":

        return (
            "CRITICAL ALERT: "
            + issue
            + ". Immediate action required. "
            "Investigate activity and reduce permissions."
        )


    elif risk == "HIGH":

        return (
            "HIGH RISK: "
            + issue
            + ". This can increase security exposure. "
            "Apply recommended security controls."
        )


    elif risk == "MEDIUM":

        return (
            "MEDIUM RISK: "
            + issue
            + ". Review configuration and improve security."
        )


    else:

        return (
            "LOW RISK: "
            + issue
            + ". Continue monitoring."
        )
