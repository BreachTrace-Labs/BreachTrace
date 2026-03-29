"""Public detector API for scanner integration."""

from detector.patterns import CredentialMatch, find_aws_credentials, mask_access_key_id
from detector.scanner import scan, scan_diff

__all__ = [
    "CredentialMatch",
    "find_aws_credentials",
    "mask_access_key_id",
    "scan",
    "scan_diff",
]
