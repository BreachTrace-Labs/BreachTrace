"""
Exposure window calculator.
Tracks when a credential was first exposed (commit timestamp)
and when it was revoked.
"""

from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from config import get_settings

settings = get_settings()


def check_key_revoked(access_key_id: str, secret_access_key: str) -> bool:
    """
    Check whether an AWS access key is still valid.
    Returns True if the key has been revoked/disabled.
    """
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        sts.get_caller_identity()
        return False  # key is still valid
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidClientTokenId":
            return True  # key is revoked
        raise


def get_exposure_window(
    exposure_start: datetime,
    exposure_end: datetime | None,
) -> tuple[datetime, datetime]:
    """Return the definitive (start, end) for forensic collection."""
    end = exposure_end or datetime.now(timezone.utc)
    return exposure_start, end
