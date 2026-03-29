from detector.scanner import scan, scan_diff


def test_scan_detects_key_in_added_line():
    diff_text = (
        "diff --git a/.env b/.env\n"
        "index 1234567..89abcde 100644\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "@@ -0,0 +1,2 @@\n"
        "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].access_key_id == "AKIAIOSFODNN7EXAMPLE"
    assert matches[0].line_number == 6
    assert matches[0].credential_hint == "AKIA****MPLE"
    assert matches[0].raw_match.endswith("(secret nearby)")


def test_scan_ignores_removed_line_credentials():
    diff_text = (
        "@@ -1,2 +0,0 @@\n"
        "-AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "-AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    matches = scan(diff_text)

    assert matches == []


def test_scan_ignores_diff_headers():
    diff_text = (
        "+++ b/AKIAIOSFODNN7EXAMPLE.txt\n"
        "--- a/AKIAIOSFODNN7EXAMPLE.txt\n"
        "@@ -1 +1 @@\n"
    )

    matches = scan(diff_text)

    assert matches == []


def test_scan_detects_key_with_secret_on_context_line():
    diff_text = (
        "@@ -10,2 +10,2 @@\n"
        " AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].access_key_id == "AKIA1234567890ABCDEF"
    assert matches[0].raw_match.endswith("(secret nearby)")


def test_scan_detects_key_with_secret_on_previous_added_line():
    diff_text = (
        "@@ -0,0 +1,2 @@\n"
        "+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "+export AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].line_number == 3
    assert matches[0].raw_match.endswith("(secret nearby)")


def test_scan_detects_key_with_secret_two_lines_away():
    diff_text = (
        "@@ -0,0 +1,4 @@\n"
        "+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
        "+comment=temporary\n"
        "+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].raw_match.endswith("(secret nearby)")


def test_scan_keeps_detection_without_secret_nearby():
    diff_text = (
        "@@ -0,0 +1 @@\n"
        "+export AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert not matches[0].raw_match.endswith("(secret nearby)")


def test_scan_deduplicates_same_key_across_hunks():
    diff_text = (
        "@@ -1 +1 @@\n"
        "+AKIAIOSFODNN7EXAMPLE\n"
        "@@ -10 +10 @@\n"
        "+AKIAIOSFODNN7EXAMPLE\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].line_number == 2


def test_scan_detects_multiple_distinct_keys():
    diff_text = (
        "@@ -0,0 +1,3 @@\n"
        "+AKIAIOSFODNN7EXAMPLE\n"
        "+some text\n"
        "+AKIA1234567890ABCDEF\n"
    )

    matches = scan(diff_text)

    assert [match.access_key_id for match in matches] == [
        "AKIAIOSFODNN7EXAMPLE",
        "AKIA1234567890ABCDEF",
    ]


def test_scan_uses_original_diff_line_numbers():
    diff_text = (
        "diff --git a/app.py b/app.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " existing_line = True\n"
        "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "+print('done')\n"
    )

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].line_number == 7


def test_scan_rejects_invalid_length_candidate():
    diff_text = "+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDE\n"
    assert scan(diff_text) == []


def test_scan_rejects_lowercase_candidate():
    diff_text = "+AWS_ACCESS_KEY_ID=akiaiosfodnn7example\n"
    assert scan(diff_text) == []


def test_scan_rejects_arn_reference():
    diff_text = "+arn:aws:iam::123456789012:user/AKIAIOSFODNN7EXAMPLE\n"
    assert scan(diff_text) == []


def test_scan_handles_json_assignment():
    diff_text = '+{"aws_access_key_id":"AKIAHF54T2G63K7J256A"}\n'

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].access_key_id == "AKIAHF54T2G63K7J256A"


def test_scan_handles_yaml_assignment():
    diff_text = "+aws_access_key_id: AKIAHF54T2G63K7J256A\n"

    matches = scan(diff_text)

    assert len(matches) == 1
    assert matches[0].context_line == "aws_access_key_id: AKIAHF54T2G63K7J256A"


def test_scan_treats_plain_text_as_candidate_input():
    plain_text = "AKIAIOSFODNN7EXAMPLE\n"

    matches = scan(plain_text)

    assert len(matches) == 1
    assert matches[0].line_number == 1


def test_scan_diff_alias_matches_scan_output():
    diff_text = "+AKIAIOSFODNN7EXAMPLE\n"

    assert scan_diff(diff_text) == scan(diff_text)
