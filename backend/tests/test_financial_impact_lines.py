"""
Structured financial impact tests (A1).

`compute_financial_impact()` (the joined string, stored in the DB and quoted in
reports) and `compute_financial_impact_lines()` (the structured form the UI
renders) are two views of one computation. The most important test here is the
drift invariant: joining available lines must reproduce the string exactly.
GCP is an exception because missing billing data is reported explicitly and
does not produce a monetary line.
"""

from datetime import datetime, timezone

import pytest

from normalizer.schema import ForensicEvent
from scorer.severity import (
    NO_FINANCIAL_IMPACT,
    GCP_FINANCIAL_UNAVAILABLE,
    FinancialImpactLine,
    compute_financial_impact,
    compute_financial_impact_lines,
)


def _event(api_action, platform="aws", resource=None, raw=None, event_source=None):
    return ForensicEvent(
        platform=platform,
        timestamp=datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc),
        api_action=api_action,
        event_source=event_source,
        affected_resource=resource,
        raw_data=raw or {},
    )


def _stripe_event(api_action, amount, currency="usd"):
    return _event(
        api_action,
        platform="stripe",
        raw={"data": {"object": {"amount": amount, "currency": currency}}},
    )


# Representative event set per platform, reused across the invariant test.
PLATFORM_FIXTURES = {
    "aws": [
        _event("RunInstances", event_source="ec2.amazonaws.com"),
        _event("GetObject", resource="prod-backup-archive.tar.gz"),
        _event("CreateDBInstance", event_source="rds.amazonaws.com"),
        _event("CreateCluster", event_source="eks.amazonaws.com"),
    ],
    "gcp": [
        _event("compute.instances.insert", platform="gcp"),
        _event("storage.objects.get", platform="gcp", resource="nightly-backup.tar.gz"),
        _event("container.clusters.create", platform="gcp"),
        _event("cloudsql.instances.create", platform="gcp"),
    ],
    "azure": [
        _event("Microsoft.Compute/virtualMachines/write", platform="azure"),
        _event("Microsoft.ContainerService/managedClusters/write", platform="azure"),
        _event("Microsoft.Sql/servers/databases/write", platform="azure"),
    ],
    "stripe": [
        _stripe_event("charge.succeeded", 41250),
        _stripe_event("refund.created", 1000),
    ],
    "twilio": [
        _event("message.sent", platform="twilio"),
        _event("call.created", platform="twilio"),
        _event("number.purchased", platform="twilio"),
    ],
}


# ==========================================================================
# The drift invariant — the reason this module exists
# ==========================================================================

@pytest.mark.parametrize("platform", sorted(set(PLATFORM_FIXTURES) - {'gcp'}))
def test_joined_lines_reproduce_the_string_exactly(platform):
    events = PLATFORM_FIXTURES[platform]
    lines = compute_financial_impact_lines(events)

    assert lines, f"{platform} fixture produced no lines"
    assert ". ".join(line.text for line in lines) == compute_financial_impact(events)


def test_drift_invariant_holds_across_platforms():
    """The multi-vendor leak: every platform's lines in one incident."""
    events = [e for fixture in PLATFORM_FIXTURES.values() for e in fixture]
    lines = compute_financial_impact_lines(events)

    assert ". ".join(line.text for line in lines) == compute_financial_impact(events)


def test_empty_input_yields_no_lines_and_the_sentinel_string():
    assert compute_financial_impact_lines([]) == []
    assert compute_financial_impact([]) == NO_FINANCIAL_IMPACT


def test_events_with_no_cost_yield_no_lines():
    """A missing GCP billing amount is unknown, not proof of zero cost."""
    events = [_event("storage.buckets.list", platform="gcp")]
    assert compute_financial_impact_lines(events) == []
    assert compute_financial_impact(events) == GCP_FINANCIAL_UNAVAILABLE


# ==========================================================================
# Actual vs estimated — the distinction the panel is built on
# ==========================================================================

def test_stripe_charge_is_marked_actual():
    """
    Stripe is the only platform where money demonstrably moved. The panel
    renders `actual` lines differently from rate estimates, so this flag has to
    be right or the UI overstates certainty.
    """
    line = compute_financial_impact_lines([_stripe_event("charge.succeeded", 124000)])[0]

    assert line.platform == "stripe"
    assert line.kind == "charge"
    assert line.actual is True
    assert line.amount == 1240.0        # minor units converted
    assert line.currency == "USD"
    assert line.quantity == 1
    assert line.unit is None            # a total, not a rate


def test_stripe_refund_is_a_separate_line():
    lines = compute_financial_impact_lines([
        _stripe_event("charge.succeeded", 20000),
        _stripe_event("refund.created", 20000),
    ])
    kinds = [line.kind for line in lines]

    # Never netted to zero — charges and refunds are different harms.
    assert "charge" in kinds
    assert "refund" in kinds
    assert all(line.actual for line in lines)


@pytest.mark.parametrize("platform", ["aws", "gcp", "azure", "twilio"])
def test_non_stripe_lines_are_estimates(platform):
    for line in compute_financial_impact_lines(PLATFORM_FIXTURES[platform]):
        assert line.actual is False, f"{platform}:{line.kind} claims to be actual money"


def test_rate_lines_carry_their_unit():
    lines = {l.kind: l for l in compute_financial_impact_lines(PLATFORM_FIXTURES["aws"])}

    assert lines["compute"].unit == "hour"
    assert lines["database"].unit == "day"
    assert lines["cluster"].unit == "hour"
    # Egress is a one-off total, not a rate.
    assert lines["egress"].unit is None


def test_quantity_reflects_event_count():
    events = [_event("RunInstances", event_source="ec2.amazonaws.com")] * 3
    assert compute_financial_impact_lines(events)[0].quantity == 3


def test_twilio_number_purchase_is_monthly():
    lines = {l.kind: l for l in compute_financial_impact_lines(PLATFORM_FIXTURES["twilio"])}
    assert lines["number"].unit == "month"


# ==========================================================================
# Multi-currency — the counter bug this change fixes
# ==========================================================================

def test_each_currency_reports_its_own_transaction_count():
    """
    Regression test. charge_count was a single shared counter emitted on every
    currency line, so a USD+EUR incident claimed the same count for both. No
    prior test was multi-currency, so it was invisible.
    """
    lines = compute_financial_impact_lines([
        _stripe_event("charge.succeeded", 10000, currency="usd"),
        _stripe_event("charge.succeeded", 20000, currency="usd"),
        _stripe_event("charge.succeeded", 30000, currency="eur"),
    ])
    by_currency = {line.currency: line for line in lines if line.kind == "charge"}

    assert by_currency["USD"].quantity == 2
    assert by_currency["EUR"].quantity == 1
    assert by_currency["USD"].amount == 300.0
    assert by_currency["EUR"].amount == 300.0


def test_multi_currency_counts_appear_in_the_rendered_text():
    text = compute_financial_impact([
        _stripe_event("charge.succeeded", 10000, currency="usd"),
        _stripe_event("charge.succeeded", 20000, currency="usd"),
        _stripe_event("charge.succeeded", 30000, currency="eur"),
    ])
    assert "(2 transaction(s))" in text
    assert "(1 transaction(s))" in text


def test_multi_currency_refunds_counted_separately():
    lines = compute_financial_impact_lines([
        _stripe_event("refund.created", 5000, currency="usd"),
        _stripe_event("refund.created", 6000, currency="gbp"),
    ])
    refunds = {line.currency: line.quantity for line in lines if line.kind == "refund"}
    assert refunds == {"USD": 1, "GBP": 1}


# ==========================================================================
# Structure and ordering
# ==========================================================================

def test_platform_ordering_is_stable():
    events = [
        _stripe_event("charge.succeeded", 100),
        _event("RunInstances", event_source="ec2.amazonaws.com"),
    ]
    forward = [l.platform for l in compute_financial_impact_lines(events)]
    reversed_ = [l.platform for l in compute_financial_impact_lines(list(reversed(events)))]

    assert forward == reversed_ == ["aws", "stripe"]


def test_lines_are_immutable():
    """Downstream code must not be able to edit a reported figure in place."""
    line = compute_financial_impact_lines([_stripe_event("charge.succeeded", 100)])[0]
    with pytest.raises(Exception):
        line.amount = 999999  # type: ignore[misc]


def test_every_line_declares_a_known_platform_and_kind():
    events = [e for fixture in PLATFORM_FIXTURES.values() for e in fixture]
    valid_platforms = {"aws", "gcp", "azure", "stripe", "twilio"}
    valid_kinds = {
        "compute", "egress", "database", "cluster",
        "charge", "refund", "messaging", "number",
    }

    for line in compute_financial_impact_lines(events):
        assert isinstance(line, FinancialImpactLine)
        assert line.platform in valid_platforms
        assert line.kind in valid_kinds
        assert line.label and line.text


def test_amount_is_never_negative():
    """Twilio prices arrive negative from the vendor; costs must read positive."""
    events = [e for fixture in PLATFORM_FIXTURES.values() for e in fixture]
    for line in compute_financial_impact_lines(events):
        if line.amount is not None:
            assert line.amount >= 0, f"{line.kind} has a negative amount"
