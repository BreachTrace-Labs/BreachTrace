"""Public detector API for scanner integration."""

from backend.detector.patterns import CredentialMatch, find_aws_credentials, mask_access_key_id
from backend.detector.scanner import scan, scan_diff

__all__ = [
    "CredentialMatch",
    "find_aws_credentials",
    "mask_access_key_id",
    "scan",
    "scan_diff",
]
