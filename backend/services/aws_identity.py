import boto3


def get_aws_account_identity() -> dict:
    """
    Get the AWS account identity associated
    with the currently configured credentials.
    """

    sts = boto3.client("sts")

    identity = sts.get_caller_identity()

    return {
        "account_id": identity.get(
            "Account"
        ),
        "arn": identity.get(
            "Arn"
        ),
        "user_id": identity.get(
            "UserId"
        ),
    }
