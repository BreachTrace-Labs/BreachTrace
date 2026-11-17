"""
Stripe and Twilio, end to end: pushed diff -> detector -> incident -> pipeline
(collect, classify, score, report) -> persisted incident.

Only the vendor API is stubbed. Everything this repository owns runs for real,
against an in-memory SQLite database, because each stage had a bug that was
invisible to the per-module tests:

  * the classifier had no Stripe/Twilio branch, so every event fell through to
    the AWS heuristic as reconnaissance/1 and a fraudulent charge scored Low;
  * the full Stripe secret key was persisted as principal_id and served by
    GET /incidents;
  * one Stripe payment was counted once per event Stripe emits for it;
  * the report used the AWS profile (CloudTrail, `aws iam delete-access-key`).
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import config
import pipeline
from classifier.rules import classify_event
from db.crud import create_incident
from db.models import Base, IncidentRecord
from detector.match_resolver import resolve_match
from detector.scanner import scan
from normalizer.schema import ForensicEvent
from reporter.gemini import generate_report
from scorer.severity import compute_financial_impact, score_incident


@compiles(JSONB, "sqlite")
def _jsonb_as_json(_type, _compiler, **_kw):
    return "JSON"


STRIPE_KEY = "sk_live_51Hq8ZtKp2Lm9XwVb7Rc4NdE"
TWILIO_SID = "AC3f9a1c7e5b2d4086a9f1e3c5b7d92a4e"
TWILIO_TOKEN = "9c2e7a4f1b8d3e6a0c5f2b9d7e4a1c8f"

PUSHED_DIFF = f"""diff --git a/.env b/.env
--- a/.env
+++ b/.env
@@ -0,0 +1,3 @@
+STRIPE_SECRET_KEY={STRIPE_KEY}
+TWILIO_ACCOUNT_SID={TWILIO_SID}
+TWILIO_AUTH_TOKEN={TWILIO_TOKEN}
"""

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


# ==========================================================================
# Harness
# ==========================================================================

@pytest.fixture
def session_factory(monkeypatch):
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(pipeline, "SessionLocal", factory)
    # Deterministic fallback report — no network.
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    return factory


def _fake_collector(platform, events):
    """Collector stand-in that records the credential the pipeline handed it."""

    class FakeCollector:
        received: list[str] = []

        def collect(self, credential, start_time, end_time):
            FakeCollector.received.append(credential)
            return [e.model_copy() for e in events]

    FakeCollector.platform = platform
    return FakeCollector


def _stripe(event_type, obj, ts=T0):
    return ForensicEvent(
        platform="stripe",
        timestamp=ts,
        api_action=event_type,
        event_source="api.stripe.com",
        affected_resource=obj.get("id"),
        resource_type=obj.get("object"),
        raw_data={"type": event_type, "data": {"object": obj}},
    )


def _twilio_message(status="sent", price=0.0079):
    return ForensicEvent(
        platform="twilio",
        timestamp=T0,
        api_action=f"message.{status}",
        event_source="api.twilio.com",
        affected_resource="+15551234567",
        resource_type="message",
        raw_data={"status": status, "price": price, "price_unit": "USD", "direction": "outbound-api"},
    )


def _detect_and_create(db, platform):
    resolved = next(
        r for r in (resolve_match(m) for m in scan(PUSHED_DIFF, include_saas=True))
        if r.platform == platform
    )
    incident = create_incident(
        db,
        credential_type=resolved.credential_type,
        credential_hint=resolved.credential_hint,
        access_key_id=resolved.access_key_id,
        repo_url="https://github.com/demo/leaky",
        commit_hash="abc123",
        exposure_start=T0,
        principal_id=resolved.principal_id,
        forensic_tier=resolved.forensic_tier,
        unavailable_reason=resolved.unavailable_reason,
    )
    return resolved, incident


# One $10 card payment, exactly as Stripe emits it.
PAYMENT_EVENTS = [
    _stripe("payment_intent.created", {"id": "pi_1", "object": "payment_intent", "amount": 1000, "currency": "usd"}),
    _stripe("payment_intent.succeeded", {"id": "pi_1", "object": "payment_intent", "amount": 1000, "amount_received": 1000, "currency": "usd"}),
    _stripe("charge.succeeded", {"id": "ch_1", "object": "charge", "amount": 1000, "payment_intent": "pi_1", "currency": "usd"}),
    _stripe("charge.updated", {"id": "ch_1", "object": "charge", "amount": 1000, "payment_intent": "pi_1", "currency": "usd"}),
]


# ==========================================================================
# Detection
# ==========================================================================

def test_push_detects_both_as_collectable_tier_one():
    resolved = {r.platform: r for r in map(resolve_match, scan(PUSHED_DIFF, include_saas=True))}

    assert resolved["stripe"].credential_type == "stripe_secret_key"
    assert resolved["stripe"].is_collectable
    assert resolved["twilio"].credential_type == "twilio_account_sid"
    assert resolved["twilio"].credential == TWILIO_SID
    assert resolved["twilio"].is_collectable


def test_removing_the_keys_does_not_refire():
    removal = PUSHED_DIFF.replace("\n+", "\n-").replace("@@ -0,0 +1,3 @@", "@@ -1,3 +0,0 @@")
    assert [m for m in scan(removal, include_saas=True)
            if resolve_match(m).platform in ("stripe", "twilio")] == []


def test_stripe_secret_is_never_stored_as_principal():
    resolved = next(
        r for r in map(resolve_match, scan(PUSHED_DIFF, include_saas=True))
        if r.platform == "stripe"
    )
    assert resolved.credential == STRIPE_KEY          # in memory, for the collector
    assert resolved.principal_id != STRIPE_KEY        # persisted + served by the API
    assert STRIPE_KEY not in (resolved.principal_id or "")
    assert "****" in resolved.principal_id


# ==========================================================================
# Classification + scoring
# ==========================================================================

@pytest.mark.parametrize("action, category, weight", [
    ("charge.succeeded", "financial_abuse", 4),
    ("payout.created", "financial_abuse", 4),
    ("account.external_account.created", "privilege_escalation", 4),
    # Unlisted Stripe types follow their resource, never AWS reconnaissance.
    ("charge.dispute.closed", "financial_abuse", 2),
    ("customer.discount.created", "resource_abuse", 2),
])
def test_stripe_events_use_the_stripe_taxonomy(action, category, weight):
    event = classify_event(_stripe(action, {"id": "x"}))
    assert (event.impact_category, event.severity_weight) == (category, weight)


@pytest.mark.parametrize("action, category, weight", [
    ("message.sent", "communication_abuse", 2),
    ("message.sending", "communication_abuse", 2),
    ("call.ringing", "communication_abuse", 3),
    ("call.no-answer", "communication_abuse", 2),
    ("message.read_by_recipient", "communication_abuse", 2),
])
def test_twilio_events_use_the_twilio_taxonomy(action, category, weight):
    event = classify_event(
        ForensicEvent(platform="twilio", timestamp=T0, api_action=action, raw_data={})
    )
    assert (event.impact_category, event.severity_weight) == (category, weight)


def test_fraudulent_charge_scores_critical():
    events = [classify_event(e.model_copy()) for e in PAYMENT_EVENTS]
    assert score_incident(events) == "Critical"


# ==========================================================================
# Financial impact
# ==========================================================================

def test_one_payment_counts_once():
    assert compute_financial_impact(PAYMENT_EVENTS) == "Stripe: 10.00 USD charged (1 transaction(s))"


def test_failed_charges_move_no_money():
    events = [
        _stripe("charge.failed", {"id": "ch_2", "object": "charge", "amount": 5000, "currency": "usd"}),
        _stripe("payment_intent.payment_failed", {"id": "pi_2", "object": "payment_intent", "amount": 5000, "currency": "usd"}),
    ]
    assert compute_financial_impact(events) == "No financial impact detected"


def test_refund_counted_once_and_by_refunded_amount():
    events = [
        # Partial refund of a $50 charge: charge.refunded carries the CHARGE.
        _stripe("charge.refunded", {"id": "ch_3", "object": "charge", "amount": 5000, "amount_refunded": 1500, "currency": "usd"}),
        _stripe("refund.created", {"id": "re_1", "object": "refund", "amount": 1500, "charge": "ch_3", "currency": "usd"}),
        _stripe("charge.refund.updated", {"id": "re_1", "object": "refund", "amount": 1500, "charge": "ch_3", "currency": "usd"}),
    ]
    assert compute_financial_impact(events) == "Stripe: 15.00 USD refunded (1 refund(s))"


def test_refund_from_charge_refunded_alone():
    events = [
        _stripe("charge.refunded", {"id": "ch_4", "object": "charge", "amount": 5000, "amount_refunded": 5000, "currency": "eur"}),
    ]
    assert compute_financial_impact(events) == "Stripe: 50.00 EUR refunded (1 refund(s))"


def test_payout_is_its_own_line_not_a_charge():
    events = [
        _stripe("payout.created", {"id": "po_1", "object": "payout", "amount": 90000, "currency": "usd"}),
        _stripe("payout.paid", {"id": "po_1", "object": "payout", "amount": 90000, "currency": "usd"}),
    ]
    assert compute_financial_impact(events) == "Stripe: 900.00 USD paid out (1 payout(s))"


def test_pending_payout_is_not_reported_as_paid():
    events = [_stripe("payout.created", {"id": "po_1", "object": "payout", "amount": 90000, "currency": "usd"})]
    assert compute_financial_impact(events) == "No financial impact detected"


def test_stripe_zero_decimal_currency_uses_whole_units():
    events = [_stripe("charge.succeeded", {"id": "ch_1", "object": "charge", "amount": 1000, "currency": "jpy"})]
    assert compute_financial_impact(events) == "Stripe: 1,000.00 JPY charged (1 transaction(s))"


def test_dispute_is_not_a_new_charge():
    events = PAYMENT_EVENTS + [
        _stripe("charge.dispute.created", {"id": "dp_1", "object": "dispute", "amount": 1000, "charge": "ch_1", "currency": "usd"}),
    ]
    assert "10.00 USD charged (1 transaction(s))" in compute_financial_impact(events)


def test_twilio_uses_billed_price_when_present():
    events = [_twilio_message(price=0.05)] * 10 + [_twilio_message(price=None)]
    # Recorded charges and pending prices remain separate.
    assert compute_financial_impact(events) == ("Twilio: 10 message(s) with recorded charges of USD 0.5000. "
                                                 "Twilio: 1 message(s) with price unavailable or pending")


# ==========================================================================
# Report
# ==========================================================================

@pytest.mark.parametrize("platform, name", [("stripe", "Stripe"), ("twilio", "Twilio")])
def test_report_uses_the_platform_not_aws(monkeypatch, platform, name):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    report = generate_report(
        events=[], overall_severity="Low", exposure_duration_seconds=60,
        affected_resources=[], source_ips=[], platform=platform,
    )
    assert name in report
    assert "aws " not in report.lower()
    assert "CloudTrail" not in report


# ==========================================================================
# Full pipeline
# ==========================================================================

def test_stripe_pipeline_end_to_end(session_factory, monkeypatch):
    collector = _fake_collector("stripe", PAYMENT_EVENTS)
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, "stripe", collector)

    db = session_factory()
    resolved, incident = _detect_and_create(db, "stripe")
    pipeline.run_collection_pipeline(
        incident.incident_id, resolved.credential, T0, platform="stripe"
    )

    stored = session_factory().get(IncidentRecord, incident.incident_id)
    assert collector.received == [STRIPE_KEY]
    assert stored.status == "complete"
    assert stored.principal_id != STRIPE_KEY
    assert stored.overall_severity == 4  # Critical
    assert {e.impact_category for e in stored.events} == {"financial_abuse"}
    assert stored.financial_impact == "Stripe: 10.00 USD charged (1 transaction(s))"
    assert stored.gdpr_flag is True      # PCI-DSS: financial abuse in the payment environment
    assert "Stripe" in stored.report_text and "CloudTrail" not in stored.report_text
    assert stored.remediation_steps


def test_twilio_pipeline_end_to_end(session_factory, monkeypatch):
    collector = _fake_collector("twilio", [_twilio_message() for _ in range(3)])
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, "twilio", collector)

    db = session_factory()
    resolved, incident = _detect_and_create(db, "twilio")
    pipeline.run_collection_pipeline(
        incident.incident_id, resolved.credential, T0, platform="twilio"
    )

    stored = session_factory().get(IncidentRecord, incident.incident_id)
    assert collector.received == [TWILIO_SID]
    assert stored.status == "complete"
    assert stored.principal_id == TWILIO_SID   # an identifier, not the secret
    assert stored.overall_severity == 2        # Medium
    assert {e.impact_category for e in stored.events} == {"communication_abuse"}
    assert stored.financial_impact == "Twilio: 3 message(s) with recorded charges of USD 0.0237"
    assert "Twilio" in stored.report_text and "CloudTrail" not in stored.report_text


@pytest.mark.parametrize('platform,credential_type', [
    ('aws', 'aws_access_key'), ('gcp', 'gcp_service_account'),
    ('azure', 'azure_service_principal'), ('stripe', 'stripe_secret_key'),
    ('twilio', 'twilio_account'),
])
def test_history_window_keeps_pre_exposure_activity_out_of_incident_impact(session_factory, monkeypatch, platform, credential_type):
    now = datetime.now(timezone.utc)
    exposure = now - timedelta(hours=1)
    historic = ForensicEvent(platform=platform, timestamp=now - timedelta(days=2),
                             api_action='historical-only', event_source='provider.example',
                             raw_data={})
    windows = []
    class Collector:
        def collect(self, credential, start_time, end_time):
            windows.append((start_time, end_time))
            return [historic]
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, platform, Collector)
    with session_factory() as db:
        incident = create_incident(db, credential_type=credential_type, credential_hint='masked',
                                   repo_url='https://github.com/example/repo', commit_hash='abc', exposure_start=exposure)
        incident_id = incident.incident_id
    pipeline.run_collection_pipeline(incident_id, 'reader-identifier', exposure, platform=platform)
    with session_factory() as db:
        stored = db.get(IncidentRecord, incident_id)
        assert stored.status == 'complete' and len(stored.events) == 1
        assert 'historical-only' not in stored.report_text
        assert 'after the detected exposure' in stored.report_text
    assert windows[0][1] - windows[0][0] == timedelta(days=30)
