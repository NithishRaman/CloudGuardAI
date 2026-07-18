def generate_fix(finding):

    issue = (
        finding.get("issue")
        or finding.get("event")
        or ""
    )


    fixes = {

        "MFA Disabled":
            {
                "action": "Enable MFA for IAM user",
                "command": "aws iam enable-mfa-device"
            },


        "AdministratorAccess Policy":
            {
                "action": "Apply least privilege IAM policy",
                "command": "Review and replace AdministratorAccess"
            },


        "Public IP exposed":
            {
                "action": "Restrict public access",
                "command": "Review Security Group inbound rules"
            },


        "Root account activity detected":
            {
                "action": "Avoid root account usage",
                "command": "Use IAM users with MFA"
            }

    }


    for key in fixes:

        if key in issue:

            return fixes[key]


    return {

        "action": "Review security configuration",

        "command": "Manual investigation required"

    }
