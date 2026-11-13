import pytest
from detector.patterns import find_azure_credentials, AzureCredentialMatch

VALID_UUID = "12345678-1234-1234-1234-123456789abc"
VALID_UUID_2 = "abcdef12-abcd-abcd-abcd-abcdef123456"
VALID_CONN_STRING = (
    "DefaultEndpointsProtocol=https;"
    "AccountName=mystorageaccount;"
    "AccountKey=" + "A" * 88 + ";"
)


# ---------------------------------------------------------------------------
# True positives — service principal UUID
# ---------------------------------------------------------------------------

def test_detects_uuid_near_client_id_keyword():
    text = f"AZURE_CLIENT_ID={VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 1
    assert sps[0].client_id == VALID_UUID


def test_detects_uuid_near_appid_keyword():
    text = f"appId: {VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 1


def test_detects_uuid_keyword_within_3_lines():
    text = f"client_id:\n  value: {VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 1
    assert sps[0].client_id == VALID_UUID.lower()


# ---------------------------------------------------------------------------
# True negatives — UUID without context
# ---------------------------------------------------------------------------

def test_uuid_without_azure_keywords_not_detected():
    # A bare UUID with no Azure keyword context should NOT match
    text = f"transaction_id = {VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 0


def test_uuid_with_non_azure_keyword_not_detected():
    text = f"order_id = {VALID_UUID}\nuser_name = alice"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 0


def test_uuid_keyword_too_far_away_not_detected():
    # keyword is 5 lines away — outside the ±3 radius
    lines = ["client_id:", "line1", "line2", "line3", "line4", f"value: {VALID_UUID}"]
    text = "\n".join(lines)
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 0


# ---------------------------------------------------------------------------
# True positives — storage connection string
# ---------------------------------------------------------------------------

def test_detects_azure_storage_connection_string():
    matches = find_azure_credentials(VALID_CONN_STRING)
    conns = [m for m in matches if m.credential_type == "azure_storage_connection"]
    assert len(conns) == 1


def test_connection_string_requires_no_context_keywords():
    # Connection string is self-identifying — no surrounding keywords needed
    text = f"conn = {VALID_CONN_STRING}"
    matches = find_azure_credentials(text)
    conns = [m for m in matches if m.credential_type == "azure_storage_connection"]
    assert len(conns) == 1


def test_connection_string_hint_is_azure_conn():
    matches = find_azure_credentials(VALID_CONN_STRING)
    conns = [m for m in matches if m.credential_type == "azure_storage_connection"]
    assert conns[0].credential_hint == "AZURE_CONN..."


def test_connection_string_client_id_is_none():
    matches = find_azure_credentials(VALID_CONN_STRING)
    conns = [m for m in matches if m.credential_type == "azure_storage_connection"]
    assert conns[0].client_id is None


# ---------------------------------------------------------------------------
# Hint format — service principal
# ---------------------------------------------------------------------------

def test_sp_credential_hint_is_first_8_chars_plus_ellipsis():
    text = f"AZURE_CLIENT_ID={VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    expected_hint = VALID_UUID.lower()[:8] + "..."
    assert sps[0].credential_hint == expected_hint


# ---------------------------------------------------------------------------
# Line number
# ---------------------------------------------------------------------------

def test_sp_line_number_correct():
    text = f"first line\nAZURE_CLIENT_ID={VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert sps[0].line_number == 2


def test_conn_string_line_number_correct():
    text = f"# config\n{VALID_CONN_STRING}"
    matches = find_azure_credentials(text)
    conns = [m for m in matches if m.credential_type == "azure_storage_connection"]
    assert conns[0].line_number == 2


# ---------------------------------------------------------------------------
# Multiple credentials in same diff
# ---------------------------------------------------------------------------

def test_multiple_uuids_near_keywords_all_detected():
    text = (
        f"client_id: {VALID_UUID}\n"
        "other config\n"
        f"applicationid: {VALID_UUID_2}"
    )
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 2
    ids = {m.client_id for m in sps}
    assert VALID_UUID.lower() in ids
    assert VALID_UUID_2.lower() in ids


def test_both_sp_and_conn_string_detected_together():
    text = f"AZURE_CLIENT_ID={VALID_UUID}\nconnection_string={VALID_CONN_STRING}"
    matches = find_azure_credentials(text)
    types = {m.credential_type for m in matches}
    assert "azure_service_principal" in types
    assert "azure_storage_connection" in types


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_text_returns_empty():
    assert find_azure_credentials("") == []


def test_duplicate_uuid_deduplicated():
    text = f"AZURE_CLIENT_ID={VALID_UUID}\nclient_id={VALID_UUID}"
    matches = find_azure_credentials(text)
    sps = [m for m in matches if m.credential_type == "azure_service_principal"]
    assert len(sps) == 1


def test_connection_string_with_short_account_key_not_detected():
    # AccountKey shorter than 64 chars — should not match
    short_key = "A" * 30
    text = f"DefaultEndpointsProtocol=https;AccountName=test;AccountKey={short_key};"
    matches = find_azure_credentials(text)
    conns = [m for m in matches if m.credential_type == "azure_storage_connection"]
    assert len(conns) == 0


# ---------------------------------------------------------------------------
# Client secret detection
# ---------------------------------------------------------------------------

# Realistic Azure AD client secret. Azure has issued secrets in the form
# "<short prefix>~<~30 more chars>" since 2021, and AZURE_CLIENT_SECRET_PATTERN
# now requires that tilde.
#
# This fixture was previously "A" * 40 — syntactically long but not shaped like
# anything Azure actually issues. The pattern that accepted it also accepted any
# long string near the word "password": JWTs, bcrypt hashes, SMTP and Redis
# passwords, other vendors' API keys. Measured against the adversarial negatives
# in tests/fixtures/gcp_azure_detection_set.csv that was 8 false positives out
# of 8 — precision 0.714. See test_gcp_azure_detection_accuracy.py.
#
# YASH: this is your file and your call to overrule. The tradeoff is recorded in
# test_legacy_tilde_less_secret_is_no_longer_detected below.
VALID_CLIENT_SECRET = "Xq7~vTn2.Kp9_Rm4-Ws8Yz1Ab3Cd6Ef0Gh"
LEGACY_CLIENT_SECRET = "A" * 40  # pre-2021 style: base64-ish, no tilde


def test_detects_client_secret_near_keyword():
    text = f"client_secret={VALID_CLIENT_SECRET}"
    matches = find_azure_credentials(text)
    secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
    assert len(secrets) == 1


def test_client_secret_hint_is_first_8_chars_plus_ellipsis():
    text = f"client_secret={VALID_CLIENT_SECRET}"
    matches = find_azure_credentials(text)
    secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
    assert secrets[0].credential_hint == VALID_CLIENT_SECRET[:8] + "..."


def test_client_secret_without_keyword_not_detected():
    text = f"some_value={VALID_CLIENT_SECRET}"
    matches = find_azure_credentials(text)
    secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
    assert len(secrets) == 0


def test_legacy_tilde_less_secret_is_no_longer_detected():
    """
    Records a deliberate recall sacrifice, so it cannot change again unnoticed.

    Pre-2021 Azure secrets were plain base64 with no tilde and are indistinguishable
    from any other long string, which is precisely what drove precision to 0.714.
    A missed credential produces no incident; a false positive produces a bogus one
    and corrupts the Track A accuracy numbers. Precision wins here.
    """
    text = f"client_secret={LEGACY_CLIENT_SECRET}"
    matches = find_azure_credentials(text)
    secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
    assert len(secrets) == 0


def test_common_non_azure_passwords_are_not_client_secrets():
    """The false positives that motivated the tighter pattern."""
    for text in (
        'password = "correcthorsebatterystaple1234567890"',
        "SMTP_PASSWORD=MailgunSmtp9876543210AbCdEfGhIjKlMnOp",
        "password: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3",
        "client_secret: ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ):
        matches = find_azure_credentials(text)
        secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
        assert len(secrets) == 0, f"false positive on: {text}"


def test_uuid_not_double_detected_as_client_secret():
    # UUID near client_id should be caught as service_principal, not also as client_secret
    text = f"client_id={VALID_UUID}\nclient_secret={VALID_UUID}"
    matches = find_azure_credentials(text)
    secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
    assert len(secrets) == 0


def test_tenant_and_subscription_ids_are_not_service_principals():
    from detector.patterns import find_azure_credentials
    text = (
        "AZURE_TENANT_ID=8f3c1d2e-1111-4222-8333-944455556666\n"
        "AZURE_CLIENT_ID=4535aaaa-bbbb-4ccc-8ddd-eeeeffffb25c\n"
        "AZURE_SUBSCRIPTION_ID=11112222-3333-4444-8555-666677778888\n"
    )
    ids = [m.client_id for m in find_azure_credentials(text) if m.credential_type == "azure_service_principal"]
    assert ids == ["4535aaaa-bbbb-4ccc-8ddd-eeeeffffb25c"]


def test_client_secret_with_client_id_is_not_a_separate_incident():
    from detector.patterns import find_azure_credentials
    text = (
        "AZURE_CLIENT_ID=4535aaaa-bbbb-4ccc-8ddd-eeeeffffb25c\n"
        "AZURE_CLIENT_SECRET=abc8Q~abcdefghijklmnopqrstuvwxyz0123456\n"
    )
    assert [m.credential_type for m in find_azure_credentials(text)] == ["azure_service_principal"]
    # A secret on its own is still reported as detection-only.
    assert [m.credential_type for m in find_azure_credentials(text.splitlines()[1])] == ["azure_client_secret"]
