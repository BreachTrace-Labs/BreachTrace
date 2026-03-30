from datetime import datetime

import boto3
from botocore.exceptions import ClientError

import config

# Error codes returned by STS / IAM when a key is no longer valid.
_REVOKED_ERROR_CODES = frozenset(
    {
        "InvalidClientTokenId",  # Key ID does not exist (deleted)
        "InvalidAccessKeyId",    # Malformed / non-existent key
        "ExpiredTokenException", # Temporary credential expired
    }
)


def record_exposure_start(commit_timestamp: str) -> datetime:
    """Parse the GitHub commit timestamp and return it as a timezone-aware datetime (UTC)."""
    return datetime.fromisoformat(commit_timestamp.replace("Z", "+00:00"))


def is_key_revoked(access_key_id: str, secret_access_key: str) -> bool:
    """
    Check whether an AWS access key is still valid by calling STS GetCallerIdentity.

    Returns True  if the key has been revoked/deleted (safe to set exposure_end).
    Returns False if the key is still active.
    Raises       for unexpected AWS errors so the caller can log them.
    """
    client = boto3.client(
        "sts",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=config.AWS_REGION,
    )
    try:
        client.get_caller_identity()
        return False  # Key still valid
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code in _REVOKED_ERROR_CODES:
            return True  # Key has been revoked or deleted
        raise  # Unexpected error — let caller handle
