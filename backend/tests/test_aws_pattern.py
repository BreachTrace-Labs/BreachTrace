# AWS regex pattern unit tests
# TODO (Yash/Day 1): write 20 tests — positive and negative cases.

import pytest
from backend.detector.patterns import find_aws_credentials

# Extensive Positive Test Cases: (test_string, expected_count, expected_key, expected_line_number)
POSITIVE_TEST_CASES = [
    ("AKIAIOSFODNN7EXAMPLE", 1, "AKIAIOSFODNN7EXAMPLE", 1),
    ("aws_key = 'AKIAIOSFODNN7EXAMPLE'", 1, "AKIAIOSFODNN7EXAMPLE", 1),
    ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", 1, "AKIAIOSFODNN7EXAMPLE", 1),
    ("The key is AKIAJ3Z3QZ3Z3QZ3Z3QZ, handle with care.", 1, "AKIAJ3Z3QZ3Z3QZ3Z3QZ", 1),
    ('{"key": "AKIAHF54T2G63K7J256A"}', 1, "AKIAHF54T2G63K7J256A", 1),
    ("AKIAIOSFODNN7EXAMPLE # This is a valid key", 1, "AKIAIOSFODNN7EXAMPLE", 1),
    # Multi-line cases
    ("First line is normal\nSecond line has the key: AKIA1234567890ABCDEF", 1, "AKIA1234567890ABCDEF", 2),
    ("AKIA1234567890ABCDEF\nAKIAFEDCBA0987654321", 2, "AKIA1234567890ABCDEF", 1),
    # Case with secret key on the same line
    ("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 1, "AKIAIOSFODNN7EXAMPLE", 1),
    # Case with secret key on the next line
    ("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 1, "AKIAIOSFODNN7EXAMPLE", 1),
]

# Extensive Negative Test Cases: (test_string)
NEGATIVE_TEST_CASES = [
    "This is just normal text without any secrets.",
    "AKIA is a prefix, but this is too short.",
    "AKIA1234567890ABCDEFG is too long for a key.",
    "BKIAIOSFODNN7EXAMPLE has the wrong prefix.",
    "akiaiosfodnn7example is lowercase and thus invalid.",
    "A random string of 20 chars: ABCDEFGHIJKLMNOPQRST",
    "An example ARN: arn:aws:iam::123456789012:user/AKIAIOSFODNN7EXAMPLE", # Keys in ARNs are often not live credentials
    "AKIA-1234-5678-90AB-CDEF contains hyphens.",
    "AKIA 1234 5678 90AB CDEF contains spaces.",
    "", # Empty string
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", # Just a secret key, no access key
]

@pytest.mark.parametrize("text, expected_count, expected_key, expected_line", POSITIVE_TEST_CASES)
def test_find_aws_credentials_positive(text, expected_count, expected_key, expected_line):
    """Tests that valid AWS keys are found correctly."""
    matches = find_aws_credentials(text)
    
    assert len(matches) >= expected_count
    
    # Find the specific match we're looking for in this test case
    specific_match_found = False
    for match in matches:
        if match.access_key_id == expected_key and match.line_number == expected_line:
            assert match.credential_type == "aws_access_key"
            assert match.credential_hint == f"{expected_key[:4]}**{expected_key[-4:]}"
            assert match.raw_match.startswith(f"{expected_key} @ line {expected_line}")
            specific_match_found = True
            break
    
    assert specific_match_found, f"Expected key {expected_key} not found in matches."

@pytest.mark.parametrize("text", NEGATIVE_TEST_CASES)
def test_find_aws_credentials_negative(text):
    """Tests that invalid or non-key strings are not detected."""
    matches = find_aws_credentials(text)
    assert len(matches) == 0

def test_finds_multiple_keys_correctly():
    """Tests that multiple distinct keys in a single text block are all found."""
    text = (
        "key1 = AKIAIOSFODNN7EXAMPLE\n"
        "unrelated line\n"
        "key2: AKIA1234567890ABCDEF"
    )
    matches = find_aws_credentials(text)
    assert len(matches) == 2
    assert matches[0].access_key_id == "AKIAIOSFODNN7EXAMPLE"
    assert matches[0].line_number == 1
    assert matches[1].access_key_id == "AKIA1234567890ABCDEF"
    assert matches[1].line_number == 3

def test_secret_key_detection_context():
    """Tests that the secret key pattern is correctly identified in context."""
    # Secret on same line
    text_same_line = (
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        "AKIAIOSFODNN7EXAMPLE"
    )
    matches_same_line = find_aws_credentials(text_same_line)
    assert len(matches_same_line) == 1
    assert matches_same_line[0].raw_match == "AKIAIOSFODNN7EXAMPLE @ line 1 (secret nearby)"

    # Secret on next line
    text_next_line = (
        "export AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
        "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    matches_next_line = find_aws_credentials(text_next_line)
    assert len(matches_next_line) == 1
    assert matches_next_line[0].raw_match == "AKIA1234567890ABCDEF @ line 1 (secret nearby)"

    # Secret two lines away should still be found
    text_two_lines_away = (
        "profile=prod\n"
        "AKIAFEDCBA0987654321\n"
        "comment line\n"
        "aws_secret_key_id=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    matches_two_lines_away = find_aws_credentials(text_two_lines_away)
    assert len(matches_two_lines_away) == 1
    assert matches_two_lines_away[0].raw_match == "AKIAFEDCBA0987654321 @ line 2 (secret nearby)"

    # Secret-like string without keywords should not be flagged as nearby secret
    text_without_keywords = (
        "AKIAZZZZZZZZZZZZZZZZ\n"
        "comment=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    matches_without_keywords = find_aws_credentials(text_without_keywords)
    assert len(matches_without_keywords) == 1
    assert matches_without_keywords[0].raw_match == "AKIAZZZZZZZZZZZZZZZZ @ line 1"

    # No secret nearby
    text_no_secret = "AKIAFEDCBA0987654321\nthis is just some other line"
    matches_no_secret = find_aws_credentials(text_no_secret)
    assert len(matches_no_secret) == 1
    assert matches_no_secret[0].raw_match == "AKIAFEDCBA0987654321 @ line 1"


def test_deduplicates_repeated_keys():
    """Tests that the same key is only returned once."""
    text = (
        "AKIAIOSFODNN7EXAMPLE\n"
        "some text\n"
        "AKIAIOSFODNN7EXAMPLE\n"
        "AKIA1234567890ABCDEF"
    )
    matches = find_aws_credentials(text)
    assert len(matches) == 2
    assert [match.access_key_id for match in matches] == [
        "AKIAIOSFODNN7EXAMPLE",
        "AKIA1234567890ABCDEF",
    ]
