"""
Cross-validation against SecretBench's published regular expressions.

WHAT THIS IS — AND IS NOT
-------------------------
SecretBench (Basak et al., MSR 2023) publishes two things: a labelled dataset of
97,479 secrets, and the 761 regular expressions used to mine them.

The **labelled dataset is not obtainable by download**. It lives in Google
BigQuery, and the project README requires contacting the authors and signing a
data protection agreement before access is granted. `test_secretbench.py` still
self-skips for that reason, and Track A's precision/recall claim remains
unvalidated against real-world code.

The **regular expressions are MIT-licensed and public**, and this file uses
them. It answers "do our patterns accept the same credential shapes as an
independent, peer-reviewed source?" — a question our own hand-built fixture
cannot answer at all, because we wrote both the detector and the samples.

It does NOT measure precision or recall on real repositories. Nothing here is a
substitute for the labelled dataset. Do not quote these results as accuracy
figures.

The fixture in fixtures/secretbench_patterns.csv is the filtered subset of the
published patterns covering the platforms we detect, checked in verbatim so the
comparison is reproducible without network access.

FIVE GAPS THIS FOUND
--------------------
Every one was invisible to the self-authored fixture, which scored 1.000/1.000
while all five were live:

  AWS       we matched AKIA only; published set is AKIA|ABIA|ACCA|ASIA.
            ASIA is STS temporary session credentials — common in leaked CI
            config, and queryable in CloudTrail exactly like a long-lived key.
  GitHub    we pinned exactly 36 body chars; published allows 36-255.
  SendGrid  we pinned 22/43; published allows 20-24 and 39-50.
  Stripe    we required a 24+ body; published allows 20-30.
  Slack     we matched xox[baprs]- only; published also covers xapp-.
"""

import csv
import os
import re

import pytest

from detector.patterns import (
    AWS_KEY_ID_PREFIXES,
    find_aws_credentials,
    find_saas_credentials,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "secretbench_patterns.csv")


def _published() -> dict[str, str]:
    with open(FIXTURE, newline="", encoding="utf-8") as handle:
        return {row["secret_type"]: row["regex"] for row in csv.DictReader(handle)}


PUBLISHED = _published()


# ==========================================================================
# Fixture integrity
# ==========================================================================

def test_published_patterns_are_available():
    assert len(PUBLISHED) >= 14
    assert "AWS API ID" in PUBLISHED
    assert "Stripe API Key" in PUBLISHED


def test_published_patterns_compile():
    """
    Two published patterns embed a `%s` keyword placeholder (Azure) and are not
    directly compilable; everything else must be a valid regex.
    """
    for secret_type, pattern in PUBLISHED.items():
        if "%s" in pattern:
            continue
        re.compile(pattern)


# ==========================================================================
# AWS — the most consequential gap
# ==========================================================================

@pytest.mark.parametrize("prefix", ["AKIA", "ABIA", "ACCA", "ASIA"])
def test_all_published_aws_key_prefixes_are_detected(prefix):
    """
    Published: `\\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\\b`.

    ASIA is the one that matters operationally — STS temporary session
    credentials. We matched AKIA only, so every leaked temporary credential
    produced no incident at all.
    """
    assert len(find_aws_credentials(prefix + "IOSFODNN7EXAMPLE")) == 1


def test_our_prefix_set_matches_the_published_one():
    published_prefixes = set(re.findall(r"[A-Z]{4}", PUBLISHED["AWS API ID"]))
    assert set(AWS_KEY_ID_PREFIXES) == published_prefixes


def test_aws_key_length_still_enforced():
    """Widening the prefix set must not relax the 16-char body."""
    assert find_aws_credentials("ASIASHORT") == []
    assert find_aws_credentials("ASIAIOSFODNN7EXAMPLETOOLONG") == []


# ==========================================================================
# Bounds that were pinned too tightly
# ==========================================================================

@pytest.mark.parametrize("body_len", [36, 40, 80, 255])
def test_github_token_length_range_matches_published(body_len):
    """Published allows 36-255; we had pinned exactly 36."""
    token = "ghp_" + ("a1B2c3D4" * 40)[:body_len]
    assert len(find_saas_credentials(f"GITHUB_TOKEN={token}")) == 1


@pytest.mark.parametrize("first,second", [(20, 39), (22, 43), (24, 50)])
def test_sendgrid_key_bounds_match_published(first, second):
    """Published allows 20-24 and 39-50; we had pinned 22 and 43."""
    key = "SG." + ("aB3dE6" * 10)[:first] + "." + ("xY7zW2" * 12)[:second]
    assert len(find_saas_credentials(key)) == 1


@pytest.mark.parametrize("body_len", [20, 24, 30])
def test_stripe_key_body_length_matches_published(body_len):
    """Published allows 20-30; we required 24+, missing shorter live keys."""
    key = "sk_live_" + ("4eC39HqLyjWDarjtT1zdp7dc" * 2)[:body_len]
    assert len(find_saas_credentials(key)) == 1


def test_slack_app_level_token_prefix_is_detected():
    """Published covers xapp- alongside xox[baprs]-; we matched only the latter."""
    assert len(find_saas_credentials("xapp-1-A012345678-1234567890123-abcdef")) == 1


@pytest.mark.parametrize("prefix", ["xoxb", "xoxp", "xoxa", "xoxr", "xoxs", "xapp"])
def test_all_published_slack_prefixes_are_detected(prefix):
    assert len(find_saas_credentials(f"{prefix}-2401234567-QWERTYuiopASDFGH")) == 1


# ==========================================================================
# Agreement on shapes we already handled
# ==========================================================================

def test_published_github_pattern_accepts_what_we_accept():
    """Round-trip: our detection must be a subset of the published pattern."""
    token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    assert re.search(PUBLISHED["Github Token"], token)
    assert len(find_saas_credentials(f"GITHUB_TOKEN={token}")) == 1


def test_published_stripe_pattern_accepts_what_we_accept():
    key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    assert re.search(PUBLISHED["Stripe API Key"], key)
    assert len(find_saas_credentials(key)) == 1


# ==========================================================================
# Where we deliberately differ — recorded so the divergence stays intentional
# ==========================================================================

def test_gcp_detection_anchors_on_key_material_like_the_published_pattern():
    """
    Published GCP pattern is `\\{[^{]+auth_provider_x509_cert_url[^}]+\\}` — it
    anchors on the KEY FILE STRUCTURE, not on the service-account email.

    Independent corroboration of the context gate: an email alone is an
    identifier, and the published source does not treat it as a credential
    either.
    """
    from detector.patterns import find_gcp_credentials

    assert "auth_provider_x509_cert_url" in PUBLISHED["GCP API Key"]
    assert find_gcp_credentials("contact svc@proj.iam.gserviceaccount.com") == []


def test_azure_published_pattern_also_requires_keyword_context():
    """
    Published Azure patterns are `(?i)(%s).{0,20}(...)` where %s is a keyword.
    The published source requires proximity to a keyword exactly as our gate
    does — the gate is not an invention of ours.
    """
    for key in ("Azure Client Secret", "Azure Key ID"):
        assert PUBLISHED[key].startswith("(?i)(%s)")


def test_aws_secret_pattern_intentionally_not_adopted():
    """
    Published AWS API Secret is a bare `[A-Za-z0-9+/]{40}` followed by a
    delimiter — any 40-char base64-ish string. Adopting it standalone would
    match git SHAs, hashes and IDs everywhere.

    We use the same shape only as CORROBORATION near an AKIA-family key
    (has_nearby_secret), never as a standalone trigger. Recorded so the
    divergence from the published set is a decision, not an oversight.
    """
    from detector.patterns import AWS_SECRET_KEY_PATTERN

    lone_hash = "a" * 40
    assert AWS_SECRET_KEY_PATTERN.search(lone_hash)          # shape matches
    assert find_aws_credentials(lone_hash) == []             # but is not an incident
