from datetime import datetime


def record_exposure_start(commit_timestamp: str) -> datetime:
    """
    Parse the commit timestamp and return it as the exposure start time (UTC).
    TODO (Ritwik/Day 2): wire into incident creation flow.
    """
    return datetime.fromisoformat(commit_timestamp.replace("Z", "+00:00"))


def is_key_revoked(access_key_id: str) -> bool:
    """
    Check whether an AWS access key is still valid by calling STS GetCallerIdentity.
    Returns True if the key has been revoked/deleted.
    TODO (Ritwik/Day 2): implement boto3 STS call with try/except.
    """
    raise NotImplementedError
