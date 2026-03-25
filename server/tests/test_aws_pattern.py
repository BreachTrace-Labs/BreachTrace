"""Tests for AWS access key regex pattern detection."""

from detector.scanner import scan


class TestAWSKeyDetection:
    """Positive and negative test cases for AWS key detection."""

    # ── Positive cases ────────────────────────────────────────────────────────

    def test_detects_standard_akia_key(self):
        diff = "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        matches = scan(diff)
        assert len(matches) == 1
        assert matches[0].access_key_id == "AKIAIOSFODNN7EXAMPLE"

    def test_detects_key_with_secret_on_next_line(self):
        diff = (
            "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        matches = scan(diff)
        assert len(matches) == 1
        assert matches[0].secret_key is not None

    def test_detects_key_in_json(self):
        diff = '+  "aws_access_key_id": "AKIAI44QH8DHBEXAMPLE"'
        matches = scan(diff)
        assert len(matches) == 1

    def test_detects_key_in_yaml(self):
        diff = "+aws_access_key_id: AKIAI44QH8DHBEXAMPLE"
        matches = scan(diff)
        assert len(matches) == 1

    def test_detects_key_in_env_file(self):
        diff = "+export AWS_KEY=AKIAI44QH8DHBEXAMPLE"
        matches = scan(diff)
        assert len(matches) == 1

    def test_hint_format(self):
        diff = "+key=AKIAIOSFODNN7EXAMPLE"
        matches = scan(diff)
        assert matches[0].hint == "AKIA****MPLE"

    # ── Negative cases ────────────────────────────────────────────────────────

    def test_rejects_short_key(self):
        diff = "+key=AKIA123"
        matches = scan(diff)
        assert len(matches) == 0

    def test_rejects_wrong_prefix(self):
        diff = "+key=BKIAIOSFODNN7EXAMPLE"
        matches = scan(diff)
        assert len(matches) == 0

    def test_rejects_lowercase_key(self):
        diff = "+key=AKIAiosfodnn7example"
        matches = scan(diff)
        assert len(matches) == 0

    def test_no_match_in_empty_diff(self):
        matches = scan("")
        assert len(matches) == 0
