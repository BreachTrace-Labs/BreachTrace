"""Diff context must describe the post-commit source within one file/hunk."""
import pytest

from detector.patterns import find_gcp_credentials, find_saas_credentials
from detector.scanner import scan


UUID = "12345678-1234-1234-1234-123456789abc"
EMAIL = "worker@demo.iam.gserviceaccount.com"
SID = "AC" + "d7a39c5e0b482f619e63a7d20c8b5f14"
KEY = "sk_Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU"


@pytest.mark.parametrize("context,value", [
    ("private_key_id=1", EMAIL),
    ("client_id=old", "CORRELATION=" + UUID),
    ("twilio configuration", SID),
    ("import sarvamai", 'api_key="' + KEY + '"'),
])
@pytest.mark.parametrize("boundary", [
    "diff --git a/b b/b\n@@ -0,0 +1 @@\n", "@@ -100 +100 @@\n",
])
def test_unrelated_files_and_hunks_cannot_supply_credential_context(context, value, boundary):
    diff = "diff --git a/a b/a\n@@ -0,0 +1 @@\n+" + context + "\n" + boundary + "+" + value
    assert scan(diff, include_saas=True) == []


@pytest.mark.parametrize("context,value", [
    ("private_key_id=1", EMAIL), ("client_id=old", "CORRELATION=" + UUID),
    ("twilio configuration", SID), ("import sarvamai", 'api_key="' + KEY + '"'),
])
def test_deleted_context_is_not_evidence_in_the_new_source(context, value):
    assert scan("-" + context + "\n+" + value, include_saas=True) == []


@pytest.mark.parametrize("source,credential_type", [
    ('client_email="' + EMAIL + '"', "gcp_service_account"),
    ("AZURE_CLIENT_ID=" + UUID, "azure_service_principal"),
    ("TWILIO_ACCOUNT_SID=" + SID, "twilio_account_sid"),
    ('SARVAM_API_KEY="' + KEY + '"', "sarvam_api_key"),
])
def test_all_families_keep_original_diff_line_numbers(source, credential_type):
    diff = "diff --git a/a b/a\nindex abc..def 100644\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+" + source
    matches = scan(diff, include_saas=True)
    assert len(matches) == 1 and matches[0].credential_type == credential_type
    assert matches[0].line_number == 6
    assert "@ line 6" in matches[0].raw_match


def test_rejected_identifier_does_not_suppress_a_later_valid_match():
    source = "serviceAccount: " + EMAIL + '\nclient_email="' + EMAIL + '"'
    matches = find_gcp_credentials(source)
    assert len(matches) == 1 and matches[0].line_number == 2
    source = SID + "\n" + "\n" * 5 + "TWILIO_ACCOUNT_SID=" + SID
    matches = find_saas_credentials(source)
    assert len(matches) == 1 and matches[0].line_number == 7


def test_deleted_comment_does_not_break_valid_post_commit_literal_assembly():
    diff = '+SARVAM_API_KEY = "' + KEY[:20] + '"\n-# removed comment\n+    + "' + KEY[20:] + '"'
    matches = scan(diff, include_saas=True)
    assert len(matches) == 1 and matches[0].platform == "sarvam"
    assert matches[0].line_number == 1 and matches[0].line_end == 3
    assert matches[0].detection_method == "literal-concatenation"


def test_structured_json_is_parsed_separately_for_each_file():
    diff = '+OTHER=1\ndiff --git a/config.json b/config.json\n@@ -0,0 +1,5 @@\n+{\n+  "sarvam": {\n+    "api_key": "' + KEY + '"\n+  }\n+}'
    matches = scan(diff, include_saas=True)
    assert len(matches) == 1 and matches[0].platform == "sarvam"
    assert matches[0].line_number == 6
    assert matches[0].detection_method == "structured-config"


def test_aws_secret_pairing_ignores_removed_and_unrelated_secret_lines():
    for secret_line in [
        "-AWS_SECRET_ACCESS_KEY=" + "aB3dE5fG7h" * 4,
        "@@ -100 +100 @@\n+AWS_SECRET_ACCESS_KEY=" + "aB3dE5fG7h" * 4,
    ]:
        matches = scan("+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" + secret_line)
        assert len(matches) == 1 and "secret nearby" not in matches[0].raw_match
