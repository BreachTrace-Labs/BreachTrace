"""
Tests for the shared match resolver (L3).

This is the seam every detector match passes through on its way to an incident.
Its failure modes are the expensive kind:

  * a Tier-2 match treated as collectable leaves the incident stuck in
    'collecting' forever;
  * a Tier-1 match treated as Tier-2 skips collection entirely, and the report
    says forensics were unavailable when they were merely never attempted;
  * a wrong platform queries the wrong audit log and reports "no activity",
    which is indistinguishable from a credential that was never used.

None of those raise. All of them produce a confident, wrong report.
"""

import pytest

from detector.match_resolver import (
    NO_PRINCIPAL_REASON,
    ResolvedMatch,
    match_credential_value,
    resolve_match,
)
from detector.patterns import (
    TIER_DETECTION_ONLY,
    TIER_FORENSIC,
    AzureCredentialMatch,
    CredentialMatch,
    GCPCredentialMatch,
    SaaSCredentialMatch,
    find_azure_credentials,
    find_gcp_credentials,
    find_saas_credentials,
)


# ==========================================================================
# AWS
# ==========================================================================

def test_resolves_aws_match():
    match = CredentialMatch(
        credential_type="aws_access_key",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        credential_hint="AKIA****MPLE",
        raw_match="AKIAIOSFODNN7EXAMPLE @ line 1",
    )
    resolved = resolve_match(match)

    assert resolved.platform == "aws"
    assert resolved.credential == "AKIAIOSFODNN7EXAMPLE"
    assert resolved.access_key_id == "AKIAIOSFODNN7EXAMPLE"
    assert resolved.principal_id is None
    assert resolved.forensic_tier == TIER_FORENSIC
    assert resolved.is_collectable is True


# ==========================================================================
# GCP / Firebase
# ==========================================================================

def test_resolves_gcp_match():
    match = find_gcp_credentials(
        '"client_email": "deploy-bot@acme-prod-4471.iam.gserviceaccount.com"'
    )[0]
    resolved = resolve_match(match)

    assert resolved.platform == "gcp"
    assert resolved.credential == "deploy-bot@acme-prod-4471.iam.gserviceaccount.com"
    # GCP has no access key ID; the identity is the service account email.
    assert resolved.access_key_id is None
    assert resolved.principal_id == resolved.credential
    assert resolved.is_collectable is False
    assert 'identifier alone' in resolved.unavailable_reason


def test_firebase_keeps_its_label_but_collects_as_gcp():
    match = find_gcp_credentials(
        '"client_email": "firebase-adminsdk-x9k2p@my-app-13ab7.iam.gserviceaccount.com"'
    )[0]
    resolved = resolve_match(match)

    assert resolved.credential_type == "firebase_service_account"
    assert resolved.platform == "gcp"
    assert resolved.is_collectable is False


# ==========================================================================
# Azure — including the G6 fix
# ==========================================================================

def test_resolves_azure_service_principal():
    match = find_azure_credentials(
        "AZURE_CLIENT_ID=3f8b2c1a-9d4e-4f7a-8b6c-1e2d3f4a5b6c"
    )[0]
    resolved = resolve_match(match)

    assert resolved.platform == "azure"
    assert resolved.credential == "3f8b2c1a-9d4e-4f7a-8b6c-1e2d3f4a5b6c"
    assert resolved.forensic_tier == TIER_FORENSIC


def test_azure_secret_without_client_id_becomes_tier_two():
    """
    G6. Azure Activity Log is queried by caller identity. A client secret or
    storage connection string identifies the secret but not the principal, so
    there is nothing to query.

    Previously this resolved to credential="" and ran a collector that returned
    nothing — an empty timeline reading as "no unauthorised activity". It is now
    recorded as detection-only with an explicit reason.
    """
    match = AzureCredentialMatch(
        credential_type="azure_client_secret",
        client_id=None,
        credential_hint="Xq7~vTn2...",
        raw_match="Azure client secret @ line 1",
    )
    resolved = resolve_match(match)

    assert resolved.forensic_tier == TIER_DETECTION_ONLY
    assert resolved.credential is None
    assert resolved.is_collectable is False
    assert resolved.unavailable_reason == NO_PRINCIPAL_REASON


def test_azure_connection_string_becomes_tier_two():
    conn = (
        "DefaultEndpointsProtocol=https;AccountName=prodstorage7;AccountKey="
        + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890abcdEFGH=="
        + ";"
    )
    match = [
        m for m in find_azure_credentials(conn)
        if m.credential_type == "azure_storage_connection"
    ][0]
    resolved = resolve_match(match)

    assert resolved.is_collectable is False
    assert resolved.unavailable_reason


def test_azure_tier_two_never_yields_an_empty_string_credential():
    """The specific G6 bug: credential == "" looks truthy enough to collect."""
    match = AzureCredentialMatch(
        credential_type="azure_client_secret",
        client_id=None,
        credential_hint="x",
        raw_match="x",
    )
    assert resolve_match(match).credential != ""
    assert resolve_match(match).credential is None


# ==========================================================================
# SaaS — Tier 1 and Tier 2
# ==========================================================================

def test_resolves_stripe_as_collectable():
    match = find_saas_credentials("sk_live_4eC39HqLyjWDarjtT1zdp7dc")[0]
    resolved = resolve_match(match)

    assert resolved.platform == "stripe"
    assert resolved.forensic_tier == TIER_FORENSIC
    assert resolved.is_collectable is True
    assert resolved.unavailable_reason is None


@pytest.mark.parametrize(
    "sample,expected_platform",
    [
        ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", "github"),
        ("npm_pMg7HqLyjWDarjtT1zdp7dcQ9vXcW2sLpR7k", "npm"),
        ("hf_QWERTYuiopASDFGHjklZXCVBNmqwer1234", "huggingface"),
    ],
)
def test_tier_two_saas_is_not_collectable(sample, expected_platform):
    resolved = resolve_match(find_saas_credentials(sample)[0])

    assert resolved.platform == expected_platform
    assert resolved.forensic_tier == TIER_DETECTION_ONLY
    assert resolved.is_collectable is False
    # Without a reason the UI panel renders empty and useless.
    assert resolved.unavailable_reason


# ==========================================================================
# Contract
# ==========================================================================

def test_unknown_match_type_raises_rather_than_guessing():
    """
    Silently defaulting an unrecognised match to AWS would query CloudTrail for
    a credential that has nothing to do with AWS and report no activity. Loud
    failure is correct here.
    """
    with pytest.raises(TypeError, match="Unrecognised detector match"):
        resolve_match(object())


def test_resolved_match_is_immutable():
    """Downstream code must not be able to mutate a resolved identity."""
    resolved = resolve_match(
        CredentialMatch(
            credential_type="aws_access_key",
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            credential_hint="AKIA****MPLE",
            raw_match="x",
        )
    )
    with pytest.raises(Exception):
        resolved.platform = "gcp"  # type: ignore[misc]


def test_match_credential_value_matches_resolution():
    match = find_saas_credentials("sk_live_4eC39HqLyjWDarjtT1zdp7dc")[0]
    assert match_credential_value(match) == resolve_match(match).credential


def test_match_credential_value_is_safe_on_unknown_types():
    """Used for request filtering, so it must not raise on junk input."""
    assert match_credential_value(object()) is None


def test_every_detector_match_type_resolves():
    """
    Sweep every match type the scanner can emit. A new detector family that
    forgets a resolver branch fails here rather than at demo time.
    """
    from detector.scanner import scan

    diff = (
        "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        '+"client_email": "sa@proj-1.iam.gserviceaccount.com"\n'
        "+AZURE_CLIENT_ID=3f8b2c1a-9d4e-4f7a-8b6c-1e2d3f4a5b6c\n"
        "+STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"
        "+GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n"
    )
    matches = scan(diff, include_saas=True)
    assert len(matches) >= 5

    for match in matches:
        resolved = resolve_match(match)
        assert isinstance(resolved, ResolvedMatch)
        assert resolved.platform
        assert resolved.credential_type
        # Every match is either collectable, or explains why it is not.
        assert resolved.is_collectable or resolved.unavailable_reason


def test_tier_one_matches_always_carry_a_credential():
    """Tier 1 without a credential is the G6 shape: collects nothing, silently."""
    from detector.scanner import scan

    diff = (
        "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "+STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"
    )
    for match in scan(diff, include_saas=True):
        resolved = resolve_match(match)
        if resolved.forensic_tier == TIER_FORENSIC:
            assert resolved.credential, f"{resolved.credential_type} is Tier 1 with no credential"
