"""
Detection tests for the SaaS + Tier-2 credential families (S3-Y5 / S3-Y6).

Every family gets three kinds of coverage:
  1. a true positive in realistic surrounding code,
  2. near-miss negatives (wrong prefix / wrong length),
  3. placeholder rejection, since docs and .env.example files are full of
     syntactically valid but fake credentials.

Precision matters more than recall here: a false positive creates a bogus
incident and, at scale, poisons the Track A accuracy numbers.
"""

import pytest

from detector.patterns import (
    TIER_DETECTION_ONLY,
    TIER_FORENSIC,
    SaaSCredentialMatch,
    find_saas_credentials,
    mask_secret,
)

# --------------------------------------------------------------------------
# Realistic sample credentials — all synthetic, none valid at any vendor.
# --------------------------------------------------------------------------
STRIPE_LIVE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_RESTRICTED = "rk_live_9Zt4vQmNbXcW2sLpR7kYhJfD"
GITHUB_PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
GITHUB_FINE = "github_pat_11ABCDEFG0qRsTuVwXyZ12_" + "b" * 59
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/QWERTYuiop1234567890zxcv"
SLACK_TOKEN = "xoxb-2401234567-2409876543-QWERTYuiopASDFGHjkl1"
NPM_TOKEN = "npm_pMg7HqLyjWDarjtT1zdp7dcQ9vXcW2sLpR7k"
SENDGRID_KEY = "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"
HUGGINGFACE_TOKEN = "hf_QWERTYuiopASDFGHjklZXCVBNmqwer1234"  # hf_ + exactly 34
POSTGRES_URI = "postgresql://appuser:s3cretPw@db.internal.example:5432/production"
MONGO_URI = "mongodb+srv://admin:R7kYhJfD2sLp@cluster0.mongodb.net/orders"
TWILIO_SID = "AC9f8e7d6c5b4a39281706f5e4d3c2b1a0"
TWILIO_TOKEN = "3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c"


def _types(matches: list[SaaSCredentialMatch]) -> set[str]:
    return {m.credential_type for m in matches}


# ==========================================================================
# Tier 1 — forensic-capable
# ==========================================================================

def test_detects_stripe_live_secret_key():
    matches = find_saas_credentials(f'STRIPE_KEY = "{STRIPE_LIVE}"')
    assert len(matches) == 1
    m = matches[0]
    assert m.credential_type == "stripe_secret_key"
    assert m.platform == "stripe"
    assert m.forensic_tier == TIER_FORENSIC
    # Tier 1 carries the identifier a collector queries by.
    assert m.principal == STRIPE_LIVE
    assert m.unavailable_reason is None


def test_detects_stripe_restricted_key():
    matches = find_saas_credentials(f"key={STRIPE_RESTRICTED}")
    assert _types(matches) == {"stripe_secret_key"}


def test_detects_stripe_test_key():
    """Test-mode keys are real detections — the harness leaks them deliberately."""
    matches = find_saas_credentials("sk_test_4eC39HqLyjWDarjtT1zdp7dc")
    assert _types(matches) == {"stripe_secret_key"}


def test_detects_twilio_account_sid():
    matches = find_saas_credentials(f'TWILIO_ACCOUNT_SID = "{TWILIO_SID}"')
    assert len(matches) == 1
    m = matches[0]
    assert m.credential_type == "twilio_account_sid"
    assert m.forensic_tier == TIER_FORENSIC
    assert m.principal == TWILIO_SID


def test_twilio_flags_paired_auth_token():
    diff = (
        "TWILIO_ACCOUNT_SID = '%s'\n"
        "TWILIO_AUTH_TOKEN = '%s'\n" % (TWILIO_SID, TWILIO_TOKEN)
    )
    matches = find_saas_credentials(diff)
    assert "(auth token nearby)" in matches[0].raw_match


def test_twilio_sid_without_twilio_context_is_not_a_credential():
    """
    `AC` + 32 hex characters is not distinctive on its own — correlation ids and
    truncated hashes take the same shape.

    This previously asserted the bare SID still matched, which encoded the bug:
    `has_keyword` was computed and then only decorated `raw_match`, so any
    AC-prefixed hex string produced a Twilio incident.
    """
    assert find_saas_credentials(f"resource id {TWILIO_SID}") == []


def test_twilio_sid_with_keyword_but_no_token_is_detected_unpaired():
    """
    The keyword is the gate, not the token: a `.env` naming TWILIO_ACCOUNT_SID
    is a genuine exposure even when the auth token lives in another file. The
    pairing signal is still recorded for the report.
    """
    matches = find_saas_credentials(f"TWILIO_ACCOUNT_SID={TWILIO_SID}")
    assert len(matches) == 1
    assert "(auth token nearby)" not in matches[0].raw_match


# ==========================================================================
# Tier 2 — detection only
# ==========================================================================

@pytest.mark.parametrize(
    "sample,expected_type,expected_platform",
    [
        (GITHUB_PAT, "github_pat", "github"),
        (GITHUB_FINE, "github_pat", "github"),
        (SLACK_WEBHOOK, "slack_webhook", "slack"),
        (SLACK_TOKEN, "slack_token", "slack"),
        (NPM_TOKEN, "npm_token", "npm"),
        (SENDGRID_KEY, "sendgrid_api_key", "sendgrid"),
        (HUGGINGFACE_TOKEN, "huggingface_token", "huggingface"),
        (POSTGRES_URI, "db_connection_string", "db"),
        (MONGO_URI, "db_connection_string", "db"),
    ],
)
def test_detects_tier2_credential(sample, expected_type, expected_platform):
    matches = find_saas_credentials(f"SECRET = {sample}")
    assert len(matches) == 1, f"expected exactly one match for {expected_type}"
    m = matches[0]
    assert m.credential_type == expected_type
    assert m.platform == expected_platform
    assert m.forensic_tier == TIER_DETECTION_ONLY


def test_tier2_matches_carry_no_principal_and_explain_why():
    """
    A Tier-2 match must never look collectable. It carries no principal, and it
    carries the reason the UI shows instead of an empty timeline.
    """
    for sample in (GITHUB_PAT, SLACK_WEBHOOK, NPM_TOKEN, SENDGRID_KEY, HUGGINGFACE_TOKEN, POSTGRES_URI):
        m = find_saas_credentials(sample)[0]
        assert m.principal is None
        assert m.unavailable_reason
        assert len(m.unavailable_reason) > 30


# ==========================================================================
# Near-miss negatives
# ==========================================================================

@pytest.mark.parametrize(
    "sample,reason",
    [
        ("sk_live_tooshort", "Stripe key body under 24 chars"),
        ("pk_live_4eC39HqLyjWDarjtT1zdp7dc", "publishable key is not a secret"),
        ("ghp_tooshort", "GitHub PAT wrong length"),
        ("ghz_16C7e42F292c6912E7710c838347Ae178B4a", "unknown GitHub prefix"),
        ("npm-pMg7HqLyjWDarjtT1zdp7dcQ9vXcW2sLpR7k", "hyphen not underscore"),
        ("hf_tooshort", "HuggingFace token wrong length"),
        ("SG.onlyonesegment", "SendGrid key missing second segment"),
        ("https://hooks.slack.com/services/T000/B000/short", "Slack webhook secret too short"),
        ("postgresql://localhost:5432/appdb", "no embedded credentials"),
        ("mongodb://cache.internal:27017/db", "no embedded credentials"),
        ("AC9f8e7d6c5b4a3928", "Twilio SID too short"),
        ("XC9f8e7d6c5b4a39281706f5e4d3c2b1a0", "Twilio SID wrong prefix"),
    ],
)
def test_rejects_near_miss(sample, reason):
    assert find_saas_credentials(sample) == [], f"false positive: {reason}"


def test_rejects_documentation_placeholders():
    """
    .env.example and README files are full of syntactically valid fakes. Flagging
    them would create bogus incidents on almost every repository.
    """
    placeholders = [
        "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghp_your_token_here_aaaaaaaaaaaaaaaaaaaa",
        "postgresql://user:password@localhost:5432/example",
        "hf_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    ]
    for sample in placeholders:
        assert find_saas_credentials(sample) == [], f"placeholder detected as real: {sample}"


def test_env_example_file_produces_no_matches():
    """Regression guard for the repo's own .env.example shape."""
    env_example = """
    STRIPE_SECRET_KEY=sk_live_your_key_here_xxxxxxxxxxxxxx
    GITHUB_TOKEN=ghp_...
    DATABASE_URL=postgresql://user:password@localhost:5432/breachtrace
    """
    assert find_saas_credentials(env_example) == []


# ==========================================================================
# Cross-cutting behaviour
# ==========================================================================

def test_multiple_platforms_in_one_diff():
    """
    The realistic leak: a single .env commit exposing several vendors at once.
    This is the case the unified cross-platform timeline exists to render.
    """
    diff = f"""
    STRIPE_SECRET_KEY={STRIPE_LIVE}
    GITHUB_TOKEN={GITHUB_PAT}
    DATABASE_URL={POSTGRES_URI}
    SENDGRID_API_KEY={SENDGRID_KEY}
    """
    matches = find_saas_credentials(diff)
    assert _types(matches) == {
        "stripe_secret_key", "github_pat", "db_connection_string", "sendgrid_api_key",
    }
    tiers = {m.credential_type: m.forensic_tier for m in matches}
    assert tiers["stripe_secret_key"] == TIER_FORENSIC
    assert tiers["github_pat"] == TIER_DETECTION_ONLY


def test_same_credential_twice_is_deduplicated():
    matches = find_saas_credentials(f"a={STRIPE_LIVE}\nb={STRIPE_LIVE}")
    assert len(matches) == 1


def test_line_numbers_are_reported():
    diff = f"line one\nline two\nSTRIPE={STRIPE_LIVE}\n"
    assert find_saas_credentials(diff)[0].line_number == 3


def test_empty_input_is_safe():
    assert find_saas_credentials("") == []


# ==========================================================================
# Masking — hints are logged and displayed, so they must not leak the secret
# ==========================================================================

def test_mask_secret_hides_the_body():
    masked = mask_secret(STRIPE_LIVE)
    assert masked.startswith("sk_live_")
    assert masked.endswith(STRIPE_LIVE[-4:])
    assert "****" in masked
    # The sensitive middle must not survive masking.
    assert STRIPE_LIVE[8:-4] not in masked


def test_every_hint_is_shorter_than_the_secret():
    for sample in (STRIPE_LIVE, GITHUB_PAT, NPM_TOKEN, SENDGRID_KEY, HUGGINGFACE_TOKEN):
        m = find_saas_credentials(sample)[0]
        assert len(m.credential_hint) < len(sample)
        assert sample not in m.credential_hint


def test_mask_secret_does_not_crash_on_short_values():
    assert "****" in mask_secret("abc")


# ==========================================================================
# Scanner integration — the opt-in flag
# ==========================================================================

def test_scan_excludes_saas_by_default():
    """
    Default must stay off until the routers can dispatch on match type. Every
    current caller reads `match.access_key_id`, which SaaSCredentialMatch does
    not define, so a default-on flag would raise AttributeError mid-pipeline.
    """
    from detector.scanner import scan

    diff = f"+STRIPE_SECRET_KEY={STRIPE_LIVE}\n"
    assert scan(diff) == []


def test_scan_includes_saas_when_requested():
    from detector.scanner import scan

    diff = f"+STRIPE_SECRET_KEY={STRIPE_LIVE}\n"
    matches = scan(diff, include_saas=True)
    assert len(matches) == 1
    assert matches[0].credential_type == "stripe_secret_key"


def test_scan_still_finds_aws_alongside_saas():
    """AWS detection must be unaffected — it is the regression gate."""
    from detector.scanner import scan

    diff = (
        "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        f"+STRIPE_SECRET_KEY={STRIPE_LIVE}\n"
    )
    types = {m.credential_type for m in scan(diff, include_saas=True)}
    assert "aws_access_key" in types
    assert "stripe_secret_key" in types


def test_saas_detection_reads_added_and_context_lines():
    """Multi-line .env diffs must still resolve, mirroring the GCP/Azure path."""
    from detector.scanner import scan

    diff = (
        "diff --git a/.env b/.env\n"
        "@@ -1,2 +1,3 @@\n"
        " EXISTING=1\n"
        f"+SENDGRID_API_KEY={SENDGRID_KEY}\n"
    )
    matches = scan(diff, include_saas=True)
    assert {m.credential_type for m in matches} == {"sendgrid_api_key"}
