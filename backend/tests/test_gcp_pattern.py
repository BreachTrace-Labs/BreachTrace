import pytest
from detector.patterns import find_gcp_credentials, GCPCredentialMatch

VALID_EMAIL = "breachtrace-experiment@breachtrace-test.iam.gserviceaccount.com"
VALID_EMAIL_2 = "another-sa@my-project-123.iam.gserviceaccount.com"
VALID_KEY_ID = "a" * 40  # 40-char hex string

SA_JSON = f"""{{
  "type": "service_account",
  "project_id": "breachtrace-test",
  "private_key_id": "{VALID_KEY_ID}",
  "client_email": "{VALID_EMAIL}",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA..."
}}"""


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------

def test_detects_client_email_in_sa_json():
    matches = find_gcp_credentials(SA_JSON)
    assert len(matches) == 1
    m = matches[0]
    assert m.credential_type == "gcp_service_account"
    assert m.client_email == VALID_EMAIL


def test_detects_bare_client_email_without_context():
    # The email pattern is specific enough — should still match even without JSON context
    text = f'client_email = "{VALID_EMAIL}"'
    matches = find_gcp_credentials(text)
    assert len(matches) == 1
    assert matches[0].client_email == VALID_EMAIL


def test_context_confirmation_flag_set_when_sa_json_present():
    matches = find_gcp_credentials(SA_JSON)
    assert "(service_account context)" in matches[0].raw_match


def test_service_account_email_without_key_material_is_not_a_leak():
    """
    A service-account email is an IDENTIFIER, not a secret — it appears in IAM
    policy bindings, k8s manifests and documentation. The credential is the
    private key.

    This test previously asserted that a bare email still matched (merely
    without the context flag), which encoded the bug: `context_confirmed` was
    computed and then used only to decorate `raw_match`, so the documented
    Pattern-2 defence never gated anything and every README mention became a
    collectable Tier-1 incident.
    """
    prose = f"Grant the Storage Admin role to {VALID_EMAIL} before deploying."
    assert find_gcp_credentials(prose) == []


def test_key_material_context_is_flagged():
    """`client_email` is itself a key-file field, so it counts as evidence."""
    text = f'client_email = "{VALID_EMAIL}"'
    matches = find_gcp_credentials(text)
    assert len(matches) == 1
    assert "(service_account context)" in matches[0].raw_match


# ---------------------------------------------------------------------------
# Hint format
# ---------------------------------------------------------------------------

def test_credential_hint_is_first_8_chars_plus_ellipsis():
    matches = find_gcp_credentials(SA_JSON)
    expected_hint = VALID_EMAIL[:8] + "..."
    assert matches[0].credential_hint == expected_hint


# ---------------------------------------------------------------------------
# Private key ID extraction
# ---------------------------------------------------------------------------

def test_extracts_private_key_id_when_present():
    matches = find_gcp_credentials(SA_JSON)
    assert matches[0].private_key_id == VALID_KEY_ID


def test_private_key_id_is_none_when_absent():
    text = f'"client_email": "{VALID_EMAIL}"'
    matches = find_gcp_credentials(text)
    assert matches[0].private_key_id is None


# ---------------------------------------------------------------------------
# Line number
# ---------------------------------------------------------------------------

def test_line_number_correct():
    text = "first line\nsecond line\n" + f'"client_email": "{VALID_EMAIL}"'
    matches = find_gcp_credentials(text)
    assert matches[0].line_number == 3


# ---------------------------------------------------------------------------
# Multiple credentials in same diff
# ---------------------------------------------------------------------------

def test_multiple_credentials_all_detected():
    text = (
        f'"client_email": "{VALID_EMAIL}"\n'
        "some unrelated line\n"
        f'"client_email": "{VALID_EMAIL_2}"'
    )
    matches = find_gcp_credentials(text)
    assert len(matches) == 2
    emails = {m.client_email for m in matches}
    assert VALID_EMAIL in emails
    assert VALID_EMAIL_2 in emails


def test_duplicate_email_deduplicated():
    text = f'"client_email": "{VALID_EMAIL}"\n"client_email": "{VALID_EMAIL}"'
    matches = find_gcp_credentials(text)
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# True negatives
# ---------------------------------------------------------------------------

def test_regular_email_not_detected():
    text = "contact us at support@example.com or admin@company.org"
    matches = find_gcp_credentials(text)
    assert len(matches) == 0


def test_non_gcp_iam_domain_not_detected():
    text = "user@project.iam.amazonaws.com"  # AWS, not GCP
    matches = find_gcp_credentials(text)
    assert len(matches) == 0


def test_empty_text_returns_empty():
    assert find_gcp_credentials("") == []


def test_private_key_id_wrong_length_not_extracted():
    # 39-char hex — too short, should not be extracted
    short_key = "a" * 39
    text = f'"private_key_id": "{short_key}"\n"client_email": "{VALID_EMAIL}"'
    matches = find_gcp_credentials(text)
    assert len(matches) == 1
    assert matches[0].private_key_id is None
