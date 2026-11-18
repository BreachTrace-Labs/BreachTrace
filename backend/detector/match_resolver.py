"""
Normalise any detector match into one shape the pipeline can act on.

The detector emits four match types, each naming its identifier differently:

    CredentialMatch      -> access_key_id   (AWS)
    GCPCredentialMatch   -> client_email
    AzureCredentialMatch -> client_id
    SaaSCredentialMatch  -> principal

Callers previously branched on `isinstance` in each router, which is how
`match.access_key_id` came to raise AttributeError on a GCP match, and how the
same dispatch ended up duplicated in webhook.py and simulate.py where the two
copies could drift. Everything funnels through `resolve_match()` instead.
"""
from __future__ import annotations

from dataclasses import dataclass

from detector.patterns import (
    TIER_DETECTION_ONLY,
    TIER_FORENSIC,
    AzureCredentialMatch,
    CredentialMatch,
    GCPCredentialMatch,
    SaaSCredentialMatch,
)

# Azure client secrets and storage connection strings identify the *secret* but
# not the *principal*, and Activity Log is queried by caller (client ID). Without
# a client ID there is nothing to query, so such an incident is recorded as
# detection-only rather than as a Tier-1 incident that silently collects nothing.
NO_PRINCIPAL_REASON = (
    "This credential was detected without an accompanying Azure client ID. "
    "Azure Activity Log is queried by caller identity, so activity cannot be "
    "attributed to this secret alone. Rotate it and check Activity Log manually "
    "for the owning service principal."
)


# Platforms whose collector principal is the secret itself, not an identifier.
_SECRET_PRINCIPAL_PLATFORMS = frozenset({"stripe"})


@dataclass(frozen=True)
class ResolvedMatch:
    """Platform-agnostic view of a detector match."""

    platform: str
    credential_type: str
    credential_hint: str
    # Identifier a collector queries by. None means nothing is collectable.
    credential: str | None
    access_key_id: str | None
    principal_id: str | None
    forensic_tier: int
    unavailable_reason: str | None

    @property
    def is_collectable(self) -> bool:
        """True when a collector can be run for this match."""
        return self.forensic_tier == TIER_FORENSIC and bool(self.credential)


def _resolve_azure(match: AzureCredentialMatch) -> ResolvedMatch:
    client_id = match.client_id or None
    if client_id:
        return ResolvedMatch(
            platform="azure",
            credential_type=match.credential_type,
            credential_hint=match.credential_hint,
            credential=client_id,
            access_key_id=None,
            principal_id=client_id,
            forensic_tier=TIER_FORENSIC,
            unavailable_reason=None,
        )

    # G6: previously this produced credential="" and collected nothing, silently.
    return ResolvedMatch(
        platform="azure",
        credential_type=match.credential_type,
        credential_hint=match.credential_hint,
        credential=None,
        access_key_id=None,
        principal_id=None,
        forensic_tier=TIER_DETECTION_ONLY,
        unavailable_reason=NO_PRINCIPAL_REASON,
    )


def resolve_match(match: object) -> ResolvedMatch:
    """Map any detector match onto ResolvedMatch."""
    if isinstance(match, GCPCredentialMatch):
        return ResolvedMatch(
            # Firebase keys are GCP service account keys; credential_type keeps
            # the Firebase label while the platform stays 'gcp' so the GCP
            # collector runs.
            platform="gcp",
            credential_type=match.credential_type,
            credential_hint=match.credential_hint,
            credential=match.client_email,
            access_key_id=None,
            principal_id=match.client_email,
            forensic_tier=TIER_FORENSIC if match.structured_key else TIER_DETECTION_ONLY,
            unavailable_reason=None if match.structured_key else (
                'A service-account identifier was found, but a complete private key was not established. '
                'An identifier alone does not prove credential exposure; review the source before investigating.'),
        )

    if isinstance(match, AzureCredentialMatch):
        return _resolve_azure(match)

    if isinstance(match, SaaSCredentialMatch):
        # For most families the principal is an identifier (a Twilio Account
        # SID). For Stripe it IS the secret key, and principal_id is persisted
        # and served by GET /incidents — storing it would re-leak the key to
        # anyone who can see the dashboard. The full key only travels in memory
        # to the collector; the stored principal is the masked hint.
        stored_principal = (
            match.credential_hint if match.platform in _SECRET_PRINCIPAL_PLATFORMS
            else match.principal
        )
        return ResolvedMatch(
            platform=match.platform,
            credential_type=match.credential_type,
            credential_hint=match.credential_hint,
            credential=match.principal,
            access_key_id=None,
            principal_id=stored_principal if match.principal else None,
            forensic_tier=match.forensic_tier,
            unavailable_reason=match.unavailable_reason,
        )

    if isinstance(match, CredentialMatch):
        return ResolvedMatch(
            platform="aws",
            credential_type=match.credential_type,
            credential_hint=match.credential_hint,
            credential=match.access_key_id,
            access_key_id=match.access_key_id,
            principal_id=None,
            forensic_tier=TIER_FORENSIC,
            unavailable_reason=None,
        )

    raise TypeError(f"Unrecognised detector match type: {type(match).__name__}")


def match_credential_value(match: object) -> str | None:
    """
    The credential identifier for a match, for filtering by a caller-supplied
    value (``POST /test/simulate`` with an explicit credential).
    """
    try:
        return resolve_match(match).credential
    except TypeError:
        return None
