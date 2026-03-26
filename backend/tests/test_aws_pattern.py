# AWS regex pattern unit tests
# TODO (Yash/Day 1): write 20 tests — positive and negative cases.

import pytest
from detector.patterns import find_aws_access_keys


def test_valid_aws_key():
    matches = find_aws_access_keys("AKIAIOSFODNN7EXAMPLE")
    assert len(matches) == 1
    assert matches[0].access_key_id == "AKIAIOSFODNN7EXAMPLE"


def test_invalid_prefix():
    matches = find_aws_access_keys("BKIAIOSFODNN7EXAMPLE")
    assert len(matches) == 0


def test_too_short():
    matches = find_aws_access_keys("AKIA12345")
    assert len(matches) == 0


def test_embedded_in_text():
    text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE rest of line"
    matches = find_aws_access_keys(text)
    assert len(matches) == 1


def test_multiple_keys():
    text = "AKIAIOSFODNN7EXAMPL1 and AKIAIOSFODNN7EXAMPL2"
    matches = find_aws_access_keys(text)
    assert len(matches) == 2
