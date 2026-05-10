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

VALID_CLIENT_SECRET = "A" * 40  # 40-char alphanumeric string


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


def test_uuid_not_double_detected_as_client_secret():
    # UUID near client_id should be caught as service_principal, not also as client_secret
    text = f"client_id={VALID_UUID}\nclient_secret={VALID_UUID}"
    matches = find_azure_credentials(text)
    secrets = [m for m in matches if m.credential_type == "azure_client_secret"]
    assert len(secrets) == 0
