"""
Tests for the credential_type -> platform mapping and forensic tier fields (L1).

The mapping decides which collector runs for an incident. Getting it wrong does
not raise — it quietly queries the wrong audit log and reports "no activity",
which looks identical to a genuinely unused credential. That silence is why
this needs direct coverage.
"""

import pytest

from db.models import (
    CREDENTIAL_TYPE_TO_PLATFORM,
    TIER_DETECTION_ONLY,
    TIER_FORENSIC,
    VALID_PLATFORMS,
    IncidentRecord,
)
from detector.patterns import _SAAS_PATTERN_SPECS


def _incident(credential_type, **kwargs):
    return IncidentRecord(credential_type=credential_type, **kwargs)


# ==========================================================================
# Platform derivation
# ==========================================================================

@pytest.mark.parametrize(
    "credential_type,expected",
    [
        ("aws_access_key", "aws"),
        ("gcp_service_account", "gcp"),
        ("azure_service_principal", "azure"),
        ("azure_client_secret", "azure"),
        ("azure_storage_connection", "azure"),
        ("stripe_secret_key", "stripe"),
        ("twilio_account_sid", "twilio"),
        ("github_pat", "github"),
        ("slack_webhook", "slack"),
        ("slack_token", "slack"),
        ("npm_token", "npm"),
        ("sendgrid_api_key", "sendgrid"),
        ("huggingface_token", "huggingface"),
        ("db_connection_string", "db"),
    ],
)
def test_platform_derived_from_credential_type(credential_type, expected):
    assert _incident(credential_type).platform == expected


def test_firebase_routes_to_the_gcp_collector():
    """
    Firebase admin SDK keys ARE GCP service account keys and their activity
    lands in Cloud Audit Logs, so they must reach the GCP collector rather than
    a nonexistent Firebase one.
    """
    assert _incident("firebase_service_account").platform == "gcp"


def test_unknown_credential_type_falls_back_to_aws():
    assert _incident("something_new").platform == "aws"


def test_platform_derivation_is_case_insensitive():
    assert _incident("STRIPE_SECRET_KEY").platform == "stripe"


def test_null_credential_type_does_not_crash():
    assert _incident(None).platform == "aws"


def test_substring_collisions_do_not_mis_route():
    """
    Regression guard for the previous `"gcp" in credential_type` approach.
    'db_connection_string' contains no platform name by luck, but the substring
    style breaks the moment two credential types share a fragment. The explicit
    map removes that whole class of bug.
    """
    assert _incident("db_connection_string").platform == "db"
    assert _incident("gcp_service_account").platform == "gcp"


# ==========================================================================
# Mapping integrity
# ==========================================================================

def test_every_mapped_platform_is_a_valid_platform():
    """A mapping target outside VALID_PLATFORMS would violate the DB CHECK."""
    for credential_type, platform in CREDENTIAL_TYPE_TO_PLATFORM.items():
        assert platform in VALID_PLATFORMS, (
            f"{credential_type} maps to {platform!r}, absent from VALID_PLATFORMS"
        )


def test_every_detected_credential_type_has_a_platform_mapping():
    """
    The detector and the mapping must not drift. An unmapped credential type
    silently falls back to AWS and queries CloudTrail for, say, a Stripe key.
    """
    detected_types = {spec[0] for spec in _SAAS_PATTERN_SPECS}
    detected_types.add("twilio_account_sid")  # handled by its own finder

    missing = detected_types - set(CREDENTIAL_TYPE_TO_PLATFORM)
    assert not missing, f"detector emits unmapped credential types: {sorted(missing)}"


def test_detector_platform_agrees_with_model_mapping():
    """Both sides name the platform; they must agree."""
    for credential_type, platform, _pattern, _tier, _reason in _SAAS_PATTERN_SPECS:
        assert CREDENTIAL_TYPE_TO_PLATFORM[credential_type] == platform, (
            f"{credential_type}: detector says {platform!r}, "
            f"model says {CREDENTIAL_TYPE_TO_PLATFORM[credential_type]!r}"
        )


# ==========================================================================
# Forensic tier
# ==========================================================================

def test_tier_defaults_to_forensic():
    """
    Existing rows predate the column and were all AWS/GCP/Azure — all Tier 1 —
    so the backfill default is correct, not merely convenient.
    """
    incident = _incident("aws_access_key")
    assert incident.forensic_tier is None or incident.forensic_tier == TIER_FORENSIC
    assert incident.is_forensic_tier is True


def test_tier_two_incident_is_not_forensic():
    incident = _incident("github_pat", forensic_tier=TIER_DETECTION_ONLY)
    assert incident.is_forensic_tier is False


def test_tier_constants_are_distinct():
    assert TIER_FORENSIC != TIER_DETECTION_ONLY


def test_detector_tiers_match_the_expected_platforms():
    """
    Pins the Tier-1/Tier-2 split so a platform cannot silently change tier.
    Moving a platform to Tier 1 without writing a collector produces incidents
    that attempt collection and report "no activity" forever.
    """
    tier_by_type = {spec[0]: spec[3] for spec in _SAAS_PATTERN_SPECS}

    assert tier_by_type["stripe_secret_key"] == TIER_FORENSIC
    for detection_only in (
        "github_pat", "slack_webhook", "slack_token", "npm_token",
        "sendgrid_api_key", "huggingface_token", "db_connection_string",
    ):
        assert tier_by_type[detection_only] == TIER_DETECTION_ONLY


def test_every_tier_two_type_explains_itself():
    """A Tier-2 incident with no reason renders an empty, useless panel."""
    for credential_type, _platform, _pattern, tier, reason in _SAAS_PATTERN_SPECS:
        if tier == TIER_DETECTION_ONLY:
            assert reason and len(reason) > 30, f"{credential_type} lacks a usable reason"


# ==========================================================================
# Firebase — a free extra platform, provided it keeps routing to GCP
# ==========================================================================

def test_firebase_key_is_labelled_separately_from_plain_gcp():
    """
    Firebase and GCP keys share a file format, so the detector must distinguish
    them by the `firebase-adminsdk-` local part. Without this the report tells a
    Firebase user their "GCP service account" leaked, naming a product they may
    not know they use.
    """
    from detector.patterns import find_gcp_credentials

    firebase = find_gcp_credentials(
        '"client_email": "firebase-adminsdk-x9k2p@my-app-13ab7.iam.gserviceaccount.com"'
    )
    plain = find_gcp_credentials(
        '"client_email": "deploy-bot@acme-prod-4471.iam.gserviceaccount.com"'
    )

    assert firebase[0].credential_type == "firebase_service_account"
    assert plain[0].credential_type == "gcp_service_account"


def test_firebase_still_collects_via_gcp():
    """The label is cosmetic; the collector routing must stay GCP."""
    assert CREDENTIAL_TYPE_TO_PLATFORM["firebase_service_account"] == "gcp"
    assert _incident("firebase_service_account").platform == "gcp"


def test_firebase_key_is_tier_one():
    """Firebase activity lands in Cloud Audit Logs, so it is fully forensic."""
    assert _incident("firebase_service_account").is_forensic_tier is True
