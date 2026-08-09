"""
Structural validation for the Stripe and Twilio taxonomies (S3-S4).

These do not test judgement calls about severity — those are Shashank's to make
and to defend in the paper. They test that every entry is well-formed, so a typo
in a category string cannot silently produce unclassified events at demo time,
and that the dicts match the shape rules.py expects for one-line registration.
"""

import pytest

from classifier.taxonomy_stripe import (
    STRIPE_API_TAXONOMY,
    VALID_CATEGORIES as STRIPE_CATEGORIES,
    VALID_SEVERITIES as STRIPE_SEVERITIES,
)
from classifier.taxonomy_twilio import (
    TWILIO_API_TAXONOMY,
    TWILIO_BULK_THRESHOLD,
    VALID_CATEGORIES as TWILIO_CATEGORIES,
    VALID_SEVERITIES as TWILIO_SEVERITIES,
)

TAXONOMIES = [
    ("stripe", STRIPE_API_TAXONOMY, STRIPE_CATEGORIES, STRIPE_SEVERITIES),
    ("twilio", TWILIO_API_TAXONOMY, TWILIO_CATEGORIES, TWILIO_SEVERITIES),
]


@pytest.mark.parametrize("name,taxonomy,categories,severities", TAXONOMIES)
def test_every_entry_is_well_formed(name, taxonomy, categories, severities):
    assert taxonomy, f"{name} taxonomy is empty"
    for action, entry in taxonomy.items():
        assert isinstance(entry, dict), f"{name}:{action} is not a dict"
        assert set(entry) == {"category", "severity", "label"}, (
            f"{name}:{action} has unexpected keys {set(entry)}"
        )
        assert entry["category"] in categories, (
            f"{name}:{action} has invalid category {entry['category']!r}"
        )
        assert entry["severity"] in severities, (
            f"{name}:{action} has invalid severity {entry['severity']!r}"
        )
        assert isinstance(entry["label"], str) and entry["label"].strip()


@pytest.mark.parametrize("name,taxonomy,_c,_s", TAXONOMIES)
def test_shape_matches_the_existing_taxonomies(name, taxonomy, _c, _s):
    """
    rules.py reads entry["category"] and entry["severity"] for every platform.
    A shape mismatch here means silent fallback to heuristics at runtime.
    """
    from classifier.taxonomy_aws import AWS_API_TAXONOMY

    reference_keys = set(next(iter(AWS_API_TAXONOMY.values())))
    for action, entry in taxonomy.items():
        assert set(entry) == reference_keys, f"{name}:{action} shape differs from AWS taxonomy"


@pytest.mark.parametrize("name,taxonomy,_c,_s", TAXONOMIES)
def test_no_duplicate_or_blank_keys(name, taxonomy, _c, _s):
    for action in taxonomy:
        assert action.strip() == action, f"{name}:{action!r} has surrounding whitespace"
        assert action, f"{name} has a blank key"


# ==========================================================================
# Stripe — the entries that carry the most weight in a report
# ==========================================================================

def test_stripe_money_movement_is_maximum_severity():
    """A charge or payout on a leaked key is immediate irreversible loss."""
    for action in ("charge.succeeded", "payment_intent.succeeded", "payout.created", "transfer.created"):
        entry = STRIPE_API_TAXONOMY[action]
        assert entry["category"] == "financial_abuse"
        assert entry["severity"] == 4, f"{action} should be severity 4"


def test_stripe_payout_redirection_is_privilege_escalation():
    """
    Adding an external bank account is how an attacker redirects future payouts.
    It is the highest-value Stripe attack and must not sit below AWS privesc.
    """
    for action in ("account.updated", "account.external_account.created"):
        entry = STRIPE_API_TAXONOMY[action]
        assert entry["category"] == "privilege_escalation"
        assert entry["severity"] == 4


def test_stripe_refunds_rank_below_charges():
    """Refunds are bounded by the original charge, so they must not outrank it."""
    assert STRIPE_API_TAXONOMY["refund.created"]["severity"] < STRIPE_API_TAXONOMY["charge.succeeded"]["severity"]


def test_stripe_reconnaissance_is_lowest_severity():
    assert STRIPE_API_TAXONOMY["balance.available"]["severity"] == 1


# ==========================================================================
# Twilio
# ==========================================================================

def test_twilio_bulk_threshold_is_far_above_the_aws_default():
    """
    BULK_THRESHOLD = 5 is tuned for AWS GetObject. Five Twilio messages is a
    normal application minute — reusing the AWS value would mark every healthy
    integration critical.
    """
    from classifier.rules import BULK_THRESHOLD

    assert TWILIO_BULK_THRESHOLD > BULK_THRESHOLD
    assert TWILIO_BULK_THRESHOLD >= 20


def test_twilio_message_sends_are_communication_abuse():
    entry = TWILIO_API_TAXONOMY["message.sent"]
    assert entry["category"] == "communication_abuse"


def test_twilio_message_body_read_is_data_access_not_recon():
    """Message bodies carry one-time passcodes and PII — reading them is a breach."""
    entry = TWILIO_API_TAXONOMY["message.read"]
    assert entry["category"] == "data_access"
    assert entry["severity"] >= 3


def test_twilio_number_purchase_is_financial_abuse():
    assert TWILIO_API_TAXONOMY["number.purchased"]["category"] == "financial_abuse"


def test_twilio_api_key_creation_is_privilege_escalation():
    entry = TWILIO_API_TAXONOMY["api_key.created"]
    assert entry["category"] == "privilege_escalation"
    assert entry["severity"] == 4


# ==========================================================================
# Registration readiness — post-merge this becomes a one-line change
# ==========================================================================

def test_taxonomies_are_importable_by_the_name_rules_will_use():
    """
    Guards the exact import rules.py will add:
        from classifier.taxonomy_stripe import STRIPE_API_TAXONOMY
        from classifier.taxonomy_twilio import TWILIO_API_TAXONOMY
    """
    import classifier.taxonomy_stripe as stripe_mod
    import classifier.taxonomy_twilio as twilio_mod

    assert hasattr(stripe_mod, "STRIPE_API_TAXONOMY")
    assert hasattr(twilio_mod, "TWILIO_API_TAXONOMY")


def test_no_key_collisions_between_platforms():
    """
    rules.py selects a taxonomy by platform, so overlap is not fatal — but an
    identical key meaning different things across platforms is a design smell
    worth surfacing rather than discovering during a demo.
    """
    overlap = set(STRIPE_API_TAXONOMY) & set(TWILIO_API_TAXONOMY)
    for action in overlap:
        stripe_cat = STRIPE_API_TAXONOMY[action]["category"]
        twilio_cat = TWILIO_API_TAXONOMY[action]["category"]
        assert stripe_cat == twilio_cat, (
            f"{action!r} means {stripe_cat} on Stripe but {twilio_cat} on Twilio"
        )
