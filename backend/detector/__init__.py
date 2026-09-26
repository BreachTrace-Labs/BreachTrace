"""Public detector API for scanner integration."""

from detector.patterns import (
    TIER_DETECTION_ONLY,
    TIER_FORENSIC,
    CredentialMatch,
    SaaSCredentialMatch,
    find_aws_credentials,
    find_saas_credentials,
    mask_access_key_id,
    mask_secret,
)
from detector.scanner import AnyCredentialMatch, scan, scan_diff

__all__ = [
    "AnyCredentialMatch",
    "CredentialMatch",
    "SaaSCredentialMatch",
    "TIER_DETECTION_ONLY",
    "TIER_FORENSIC",
    "find_aws_credentials",
    "find_saas_credentials",
    "mask_access_key_id",
    "mask_secret",
    "scan",
    "scan_diff",
]
