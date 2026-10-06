"""
Multi-platform financial impact tests (S3-S2).

Before this change compute_financial_impact() matched AWS action names only, so
every GCP, Azure, Stripe and Twilio incident reported "No financial impact
detected" regardless of what the attacker actually did. These tests pin the
per-platform behaviour and, critically, that AWS output is unchanged.
"""

import pytest

from normalizer.schema import ForensicEvent
from scorer.severity import compute_financial_impact

from datetime import datetime, timezone


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


# ==========================================================================
# Regression guard — AWS must not change
# ==========================================================================

def test_aws_output_is_unchanged():
    events = [_event("RunInstances", event_source="ec2.amazonaws.com")] * 2
    result = compute_financial_impact(events)
    assert result == "EC2: 2x t2.micro at $0.02/hr"


def test_events_without_platform_are_treated_as_aws():
    """Schema defaults platform to 'aws'; older rows may carry nothing at all."""
    event = _event("RunInstances", event_source="ec2.amazonaws.com")
    event.platform = None
    assert "EC2" in compute_financial_impact([event])


# ==========================================================================
# GCP
# ==========================================================================

def test_gcp_compute_instance_creation_has_cost():
    """The regression this task exists to fix: GCP used to always report zero."""
    result = compute_financial_impact([_event("compute.instances.insert", platform="gcp")])
    assert "Compute Engine" in result
    assert "e2-micro" in result
    assert result != "No financial impact detected"


def test_gcp_counts_multiple_instances():
    events = [_event("compute.instances.insert", platform="gcp")] * 3
    assert "3x e2-micro" in compute_financial_impact(events)


def test_gcp_bulk_storage_read_has_egress_cost():
    events = [
        _event("storage.objects.get", platform="gcp", resource="prod-backup-archive.tar.gz")
    ]
    assert "Cloud Storage egress" in compute_financial_impact(events)


def test_gcp_small_object_read_has_no_egress_cost():
    events = [_event("storage.objects.get", platform="gcp", resource="config.json")]
    assert compute_financial_impact(events) == "No financial impact detected"


def test_gcp_gke_cluster_creation():
    assert "GKE" in compute_financial_impact(
        [_event("container.clusters.create", platform="gcp")]
    )


def test_gcp_cloudsql_creation():
    assert "Cloud SQL" in compute_financial_impact(
        [_event("cloudsql.instances.create", platform="gcp")]
    )


def test_gcp_reconnaissance_alone_costs_nothing():
    events = [_event("storage.buckets.list", platform="gcp")]
    assert compute_financial_impact(events) == "No financial impact detected"


# ==========================================================================
# Azure
# ==========================================================================

def test_azure_vm_creation_has_cost():
    events = [_event("Microsoft.Compute/virtualMachines/write", platform="azure")]
    result = compute_financial_impact(events)
    assert "Virtual Machines" in result
    assert "B1s" in result


def test_azure_matching_is_case_insensitive():
    """Activity Log casing is inconsistent, so matching must not depend on it."""
    lower = compute_financial_impact(
        [_event("microsoft.compute/virtualmachines/write", platform="azure")]
    )
    upper = compute_financial_impact(
        [_event("MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", platform="azure")]
    )
    assert "Virtual Machines" in lower
    assert lower == upper


def test_azure_aks_cluster_creation():
    events = [_event("Microsoft.ContainerService/managedClusters/write", platform="azure")]
    assert "AKS" in compute_financial_impact(events)


def test_azure_sql_database_creation():
    events = [_event("Microsoft.Sql/servers/databases/write", platform="azure")]
    assert "Azure SQL" in compute_financial_impact(events)


def test_azure_read_operations_alone_cost_nothing():
    events = [_event("Microsoft.Storage/storageAccounts/read", platform="azure")]
    assert compute_financial_impact(events) == "No financial impact detected"


# ==========================================================================
# Stripe — real money, not an estimate
# ==========================================================================

def test_stripe_reports_actual_charged_amount():
    """
    Stripe amounts arrive in minor units (cents). Reporting 41250 instead of
    412.50 would overstate the impact by 100x in the incident report.
    """
    events = [_stripe_event("charge.succeeded", 41250)]
    result = compute_financial_impact(events)
    assert "412.50 USD charged" in result


def test_stripe_sums_multiple_charges():
    events = [_stripe_event("charge.succeeded", 10000), _stripe_event("charge.succeeded", 5050)]
    assert "150.50 USD charged" in compute_financial_impact(events)
    assert "2 transaction(s)" in compute_financial_impact(events)


def test_stripe_refunds_reported_separately_from_charges():
    """Charges and refunds are different harms and must not be netted to zero."""
    events = [_stripe_event("charge.succeeded", 20000), _stripe_event("refund.created", 20000)]
    result = compute_financial_impact(events)
    assert "charged" in result
    assert "refunded" in result
    assert result != "No financial impact detected"


def test_stripe_respects_non_usd_currency():
    events = [_stripe_event("charge.succeeded", 25000, currency="eur")]
    assert "250.00 EUR charged" in compute_financial_impact(events)


def test_stripe_payment_intent_counts_as_a_charge():
    assert "charged" in compute_financial_impact([_stripe_event("payment_intent.succeeded", 999)])


def test_stripe_event_without_amount_is_ignored():
    """A customer lookup carries no amount and must not crash or invent a figure."""
    events = [_event("customer.retrieved", platform="stripe", raw={"data": {"object": {}}})]
    assert compute_financial_impact(events) == "No financial impact detected"


def test_stripe_malformed_raw_data_does_not_crash():
    for raw in ({}, {"data": None}, {"data": {"object": None}}, {"data": {"object": {"amount": "x"}}}):
        events = [_event("charge.created", platform="stripe", raw=raw)]
        assert compute_financial_impact(events) == "No financial impact detected"


# ==========================================================================
# Twilio
# ==========================================================================

def test_twilio_message_sends_have_cost():
    events = [_event("message.sent", platform="twilio")] * 100
    result = compute_financial_impact(events)
    assert "100 message(s)" in result
    assert "$0.79" in result


def test_twilio_calls_have_cost():
    assert "call(s)" in compute_financial_impact([_event("call.created", platform="twilio")])


def test_twilio_number_purchase_has_monthly_cost():
    events = [_event("number.purchased", platform="twilio")]
    assert "number(s) purchased" in compute_financial_impact(events)


# ==========================================================================
# Mixed-platform incidents — the realistic multi-vendor leak
# ==========================================================================

def test_multi_platform_incident_reports_every_platform():
    """
    One commit leaking an AWS key and a Stripe key is the demo scenario. Both
    costs must appear in the same report.
    """
    events = [
        _event("RunInstances", event_source="ec2.amazonaws.com"),
        _event("compute.instances.insert", platform="gcp"),
        _stripe_event("charge.succeeded", 50000),
    ]
    result = compute_financial_impact(events)
    assert "EC2" in result
    assert "Compute Engine" in result
    assert "500.00 USD charged" in result


def test_platform_ordering_is_stable():
    """Report text must not churn between identical runs."""
    events = [
        _stripe_event("charge.succeeded", 100),
        _event("RunInstances", event_source="ec2.amazonaws.com"),
    ]
    assert compute_financial_impact(events) == compute_financial_impact(list(reversed(events)))
    assert compute_financial_impact(events).startswith("EC2")


def test_empty_input_unchanged():
    assert compute_financial_impact([]) == "No financial impact detected"


def test_unknown_platform_is_ignored_gracefully():
    events = [_event("something.happened", platform="digitalocean")]
    assert compute_financial_impact(events) == "No financial impact detected"
