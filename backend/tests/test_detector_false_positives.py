"""
Regression tests for three confirmed false-positive paths.

All three were found by code review, reproduced against the live detector, and
shared a single shape: a defence was **computed and then not enforced**. The
context flag was calculated, used to append a note to `raw_match`, and the match
appended unconditionally. The documented protection existed only in the string.

They are grouped here rather than scattered across the per-platform files
because the failure mode is the same, and because the accuracy fixture reported
Precision=1.000 while every one of them was live — the benchmark contained no
sample that could fail. These are the samples that could.

  FP1  Any GCP service-account email, anywhere, created a Tier-1 incident.
       A README line documenting which account to grant a role to was a
       collectable credential leak.

  FP2  Deleting a leaked credential created a NEW incident. The scanner passed
       every diff line to the non-AWS detectors including `-` removals, so the
       remediation commit re-fired the alarm for every platform except AWS.

  FP3  `AC` + 32 hex characters anywhere was a Twilio incident.
"""

import pytest

from detector.patterns import find_gcp_credentials, find_saas_credentials
from detector.scanner import scan


# ==========================================================================
# FP1 — GCP: an identifier is not a credential
# ==========================================================================

REAL_SA_EMAIL = "ci-runner@my-proj-14.iam.gserviceaccount.com"


@pytest.mark.parametrize(
    "snippet,context",
    [
        (f"Grant the Storage Admin role to {REAL_SA_EMAIL} before deploying.", "README prose"),
        (f"# The deployer account is {REAL_SA_EMAIL}", "code comment"),
        (f"members:\n  - serviceAccount:{REAL_SA_EMAIL}", "IAM policy binding"),
        (f"Error: permission denied for {REAL_SA_EMAIL}", "log line"),
        (f"| Account | {REAL_SA_EMAIL} | read-only |", "markdown table"),
        (f"annotations:\n  iam.gke.io/gcp-service-account: {REAL_SA_EMAIL}", "k8s annotation"),
    ],
)
def test_service_account_email_without_key_material_is_not_a_leak(snippet, context):
    """
    A `*.iam.gserviceaccount.com` address is an identifier, not a secret. It
    appears in IAM bindings, manifests and documentation by design. The
    credential is the private key.
    """
    assert find_gcp_credentials(snippet) == [], f"false positive in {context}"


@pytest.mark.parametrize(
    "snippet,context",
    [
        ('{"type": "service_account", "client_email": "%s"}' % REAL_SA_EMAIL, "key file"),
        ('"client_email": "%s"' % REAL_SA_EMAIL, "key-file field"),
        ("GOOGLE_SA_EMAIL=%s" % REAL_SA_EMAIL, "credential env var"),
        ("GCP_SA=%s" % REAL_SA_EMAIL, "gcp_sa env var"),
        ('  "private_key_id": "a"*40,\n  "client_email": "%s"' % REAL_SA_EMAIL, "key id nearby"),
    ],
)
def test_key_material_context_still_detected(snippet, context):
    """The gate must not cost real detections — these all carry key material."""
    assert len(find_gcp_credentials(snippet)) == 1, f"missed a real leak in {context}"


# ==========================================================================
# FP2 — deleting a credential is remediation, not a new leak
# ==========================================================================

REMOVAL_DIFF = """diff --git a/.env b/.env
--- a/.env
+++ b/.env
-GCP_SA=leaked@proj-1.iam.gserviceaccount.com
-AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
-TWILIO_ACCOUNT_SID=AC9f8e7d6c5b4a39281706f5e4d3c2b1a0
-AZURE_CLIENT_ID=3f8b2c1a-9d4e-4f7a-8b6c-1e2d3f4a5b6c
-STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
"""


def test_removing_credentials_creates_no_incidents():
    """
    The remediation commit must not re-fire the alarm. AWS always filtered to
    added lines; GCP, Azure and the SaaS families did not, so every platform
    except AWS raised a fresh incident when the key was deleted.
    """
    assert scan(REMOVAL_DIFF, include_saas=True) == []


def test_adding_the_same_credentials_does_create_incidents():
    """The mirror image — proves the filter is on polarity, not on the values."""
    addition = REMOVAL_DIFF.replace("\n-", "\n+")
    found = {m.credential_type for m in scan(addition, include_saas=True)}

    assert "aws_access_key" in found
    assert "gcp_service_account" in found
    assert "twilio_account_sid" in found
    assert "stripe_secret_key" in found


def test_context_lines_still_supply_context_but_do_not_match():
    """
    A key file whose surrounding lines are unchanged must still be recognised:
    the context window spans the full diff, only the MATCHING line has to be an
    addition. Otherwise the polarity fix would break multi-line key detection.
    """
    diff = (
        "--- a/sa.json\n"
        "+++ b/sa.json\n"
        ' {"type": "service_account",\n'
        '+ "client_email": "deploy@proj-9.iam.gserviceaccount.com",\n'
        ' "project_id": "proj-9"}\n'
    )
    matches = scan(diff)
    assert len(matches) == 1
    assert matches[0].credential_type == "gcp_service_account"


def test_unchanged_context_line_alone_does_not_fire():
    """A credential present only as unchanged context is not newly exposed."""
    diff = (
        "--- a/sa.json\n"
        "+++ b/sa.json\n"
        ' {"type": "service_account", "client_email": "old@proj-9.iam.gserviceaccount.com"}\n'
        "+# unrelated comment\n"
    )
    assert scan(diff) == []


# ==========================================================================
# FP3 — Twilio: AC + hex is not distinctive
# ==========================================================================

TWILIO_SID = "AC9f8e7d6c5b4a39281706f5e4d3c2b1a0"


@pytest.mark.parametrize(
    "snippet,context",
    [
        (f"resource_id = {TWILIO_SID}", "bare assignment"),
        (f"correlation = {TWILIO_SID}", "correlation id"),
        (f"# see record {TWILIO_SID}", "comment"),
        ("checksum = ACdeadbeefdeadbeefdeadbeefdeadbeef", "hash-like string"),
    ],
)
def test_ac_hex_without_twilio_context_is_not_a_credential(snippet, context):
    assert find_saas_credentials(snippet) == [], f"false positive: {context}"


@pytest.mark.parametrize(
    "snippet",
    [
        f"TWILIO_ACCOUNT_SID={TWILIO_SID}",
        f"twilio:\n  account_sid: {TWILIO_SID}",
        f"accountSid = '{TWILIO_SID}'",
    ],
)
def test_twilio_context_still_detected(snippet):
    """The gate must not cost real Twilio detections."""
    assert len(find_saas_credentials(snippet)) == 1


# ==========================================================================
# The shared shape — a computed flag that is never enforced
# ==========================================================================

def test_computed_context_flags_actually_gate():
    """
    All three bugs were the same mistake: calculate a defence, use it only to
    decorate a string, append the match regardless. This asserts the gates
    change the OUTCOME, not just the label — the property each original bug
    violated.
    """
    # GCP: no key material -> no match at all, not a match without a flag.
    assert find_gcp_credentials(f"see {REAL_SA_EMAIL}") == []
    # Twilio: no keyword -> no match at all.
    assert find_saas_credentials(f"id {TWILIO_SID}") == []
    # And with the context present, exactly one match each.
    assert len(find_gcp_credentials(f'"client_email": "{REAL_SA_EMAIL}"')) == 1
    assert len(find_saas_credentials(f"TWILIO_ACCOUNT_SID={TWILIO_SID}")) == 1
