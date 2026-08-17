"""
Field-mapping tests for the Stripe and Twilio collectors (L2).

The SDKs are stubbed rather than installed: these tests pin the mapping from
each vendor's payload shape onto ForensicEvent, which is where collectors
actually break. Live API behaviour is a separate, credentialed concern.

The mapping is worth this much coverage because its failures are silent. A
wrong field yields an event that classifies as reconnaissance instead of
financial abuse, and the report reads as reassuring rather than alarming.
"""

import sys
import types
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest


# ==========================================================================
# SDK stubs — installed before the collectors are imported
# ==========================================================================

@pytest.fixture
def stripe_sdk(monkeypatch):
    """Minimal stand-in for the `stripe` package."""
    module = types.ModuleType("stripe")
    module.Event = MagicMock()
    monkeypatch.setitem(sys.modules, "stripe", module)
    return module


@pytest.fixture
def twilio_sdk(monkeypatch):
    """Minimal stand-in for `twilio.rest`."""
    twilio_module = types.ModuleType("twilio")
    rest_module = types.ModuleType("twilio.rest")
    client_instance = MagicMock()
    rest_module.Client = MagicMock(return_value=client_instance)
    twilio_module.rest = rest_module
    monkeypatch.setitem(sys.modules, "twilio", twilio_module)
    monkeypatch.setitem(sys.modules, "twilio.rest", rest_module)
    return client_instance


def _stripe_event(event_type="charge.succeeded", amount=41250, created=None, **overrides):
    payload = {
        "id": "evt_1abc",
        "type": event_type,
        "created": created if created is not None else 1_775_000_000,
        "request": {"id": "req_xyz", "idempotency_key": "idem_1"},
        "data": {
            "object": {
                "id": "ch_1abc",
                "object": "charge",
                "amount": amount,
                "currency": "usd",
            }
        },
    }
    payload.update(overrides)
    event = MagicMock()
    event.to_dict.return_value = payload
    event.id = payload["id"]
    return event


def _page(data, has_more=False):
    page = MagicMock()
    page.data = data
    page.has_more = has_more
    return page


# ==========================================================================
# Stripe
# ==========================================================================

def test_stripe_maps_event_fields(stripe_sdk, monkeypatch):
    from collectors.stripe import StripeEventsCollector

    stripe_sdk.Event.list.return_value = _page([_stripe_event()])
    collector = StripeEventsCollector(api_key="sk_test_x")

    events = collector.collect(
        "sk_live_leaked",
        datetime(2026, 8, 1, tzinfo=timezone.utc),
        datetime(2026, 8, 2, tzinfo=timezone.utc),
    )

    assert len(events) == 1
    event = events[0]
    assert event.platform == "stripe"
    # api_action must be the Stripe event type so taxonomy_stripe keys match.
    assert event.api_action == "charge.succeeded"
    assert event.event_source == "api.stripe.com"
    assert event.affected_resource == "ch_1abc"
    assert event.resource_type == "charge"
    assert event.success is True


def test_stripe_preserves_amount_for_financial_impact(stripe_sdk):
    """
    compute_financial_impact() reads data.object.amount out of raw_data. If the
    collector flattens or drops it, Stripe silently reports zero financial harm
    — the one platform where the figure is real money.
    """
    from collectors.stripe import StripeEventsCollector
    from scorer.severity import compute_financial_impact

    stripe_sdk.Event.list.return_value = _page([_stripe_event(amount=41250)])
    collector = StripeEventsCollector(api_key="sk_test_x")
    events = collector.collect("sk_live_x", datetime(2026, 8, 1), datetime(2026, 8, 2))

    assert "412.50 USD charged" in compute_financial_impact(events)


def test_stripe_timestamp_converted_from_unix(stripe_sdk):
    from collectors.stripe import StripeEventsCollector

    stripe_sdk.Event.list.return_value = _page([_stripe_event(created=1_775_000_000)])
    collector = StripeEventsCollector(api_key="sk_test_x")
    event = collector.collect("sk_live_x", datetime(2026, 8, 1), datetime(2026, 8, 2))[0]

    assert event.timestamp == datetime.fromtimestamp(1_775_000_000, tz=timezone.utc)


def test_stripe_source_ip_is_none_not_invented(stripe_sdk):
    """
    Stripe events carry no source IP. Fabricating one would put a false fact in
    a forensic report; None renders honestly as "unknown IP".
    """
    from collectors.stripe import StripeEventsCollector

    stripe_sdk.Event.list.return_value = _page([_stripe_event()])
    collector = StripeEventsCollector(api_key="sk_test_x")
    assert collector.collect("sk_live_x", datetime(2026, 8, 1), datetime(2026, 8, 2))[0].source_ip is None


def test_stripe_paginates(stripe_sdk):
    from collectors.stripe import StripeEventsCollector

    first = _page([_stripe_event() for _ in range(3)], has_more=True)
    second = _page([_stripe_event() for _ in range(2)], has_more=False)
    stripe_sdk.Event.list.side_effect = [first, second]

    collector = StripeEventsCollector(api_key="sk_test_x")
    events = collector.collect("sk_live_x", datetime(2026, 8, 1), datetime(2026, 8, 2))

    assert len(events) == 5
    assert stripe_sdk.Event.list.call_count == 2


def test_stripe_empty_window_returns_empty_list(stripe_sdk):
    from collectors.stripe import StripeEventsCollector

    stripe_sdk.Event.list.return_value = _page([])
    collector = StripeEventsCollector(api_key="sk_test_x")
    assert collector.collect("sk_live_x", datetime(2026, 8, 1), datetime(2026, 8, 2)) == []


def test_stripe_window_sent_as_unix_seconds(stripe_sdk):
    from collectors.stripe import StripeEventsCollector

    stripe_sdk.Event.list.return_value = _page([])
    collector = StripeEventsCollector(api_key="sk_test_x")
    collector.collect(
        "sk_live_x",
        datetime(2026, 8, 1, tzinfo=timezone.utc),
        datetime(2026, 8, 2, tzinfo=timezone.utc),
    )

    created = stripe_sdk.Event.list.call_args.kwargs["created"]
    assert created["gte"] == int(datetime(2026, 8, 1, tzinfo=timezone.utc).timestamp())
    assert created["lte"] == int(datetime(2026, 8, 2, tzinfo=timezone.utc).timestamp())


def test_stripe_naive_datetime_treated_as_utc(stripe_sdk):
    """A naive datetime must not be read as local time, shifting the window."""
    from collectors.stripe import StripeEventsCollector

    stripe_sdk.Event.list.return_value = _page([])
    collector = StripeEventsCollector(api_key="sk_test_x")
    collector.collect("sk_live_x", datetime(2026, 8, 1), datetime(2026, 8, 2))

    created = stripe_sdk.Event.list.call_args.kwargs["created"]
    assert created["gte"] == int(datetime(2026, 8, 1, tzinfo=timezone.utc).timestamp())


def test_stripe_requires_an_api_key(stripe_sdk, monkeypatch):
    import config
    from collectors.stripe import StripeEventsCollector

    monkeypatch.setattr(config, "STRIPE_API_KEY", "", raising=False)
    with pytest.raises(ValueError, match="Stripe API key"):
        StripeEventsCollector()


# ==========================================================================
# Twilio
# ==========================================================================

def _twilio_message(status="sent", to="+15551234567", price="-0.0079", body="Your code is 123456"):
    message = MagicMock()
    message.sid = "SM1abc"
    message.status = status
    message.to = to
    message.from_ = "+15559876543"
    message.date_sent = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
    message.price = price
    message.price_unit = "USD"
    message.num_segments = "1"
    message.body = body
    message.error_code = None
    message.account_sid = "AC123"
    return message


def _twilio_call(status="completed", to="+15551234567"):
    call = MagicMock()
    call.sid = "CA1abc"
    call.status = status
    call.to = to
    call.from_ = "+15559876543"
    call.start_time = datetime(2026, 8, 1, 12, 5, tzinfo=timezone.utc)
    call.price = "-0.014"
    call.price_unit = "USD"
    call.duration = "42"
    call.direction = "outbound-api"
    call.account_sid = "AC123"
    return call


def test_twilio_maps_message_fields(twilio_sdk):
    from collectors.twilio import TwilioUsageCollector

    twilio_sdk.messages.list.return_value = [_twilio_message()]
    twilio_sdk.calls.list.return_value = []

    collector = TwilioUsageCollector(account_sid="AC123", auth_token="tok")
    events = collector.collect("AC123", datetime(2026, 8, 1), datetime(2026, 8, 2))

    assert len(events) == 1
    event = events[0]
    assert event.platform == "twilio"
    # Must match taxonomy_twilio keys ("message.sent").
    assert event.api_action == "message.sent"
    # The destination number is the affected resource for spam abuse.
    assert event.affected_resource == "+15551234567"
    assert event.resource_type == "message"
    assert event.success is True


def test_twilio_does_not_store_message_bodies(twilio_sdk):
    """
    Message bodies routinely carry one-time passcodes and personal data.
    Storing them would move that content into our database and into Gemini
    prompts. Only the length is kept.
    """
    from collectors.twilio import TwilioUsageCollector

    secret_body = "Your bank OTP is 998877"
    twilio_sdk.messages.list.return_value = [_twilio_message(body=secret_body)]
    twilio_sdk.calls.list.return_value = []

    collector = TwilioUsageCollector(account_sid="AC123", auth_token="tok")
    event = collector.collect("AC123", datetime(2026, 8, 1), datetime(2026, 8, 2))[0]

    assert secret_body not in str(event.raw_data)
    assert event.raw_data["body_length"] == len(secret_body)


def test_twilio_price_normalised_to_positive(twilio_sdk):
    """Twilio reports price as a negative amount charged."""
    from collectors.twilio import TwilioUsageCollector

    twilio_sdk.messages.list.return_value = [_twilio_message(price="-0.0079")]
    twilio_sdk.calls.list.return_value = []

    collector = TwilioUsageCollector(account_sid="AC123", auth_token="tok")
    event = collector.collect("AC123", datetime(2026, 8, 1), datetime(2026, 8, 2))[0]

    assert event.raw_data["price"] == pytest.approx(0.0079)


def test_twilio_failed_message_marked_unsuccessful(twilio_sdk):
    from collectors.twilio import TwilioUsageCollector

    twilio_sdk.messages.list.return_value = [_twilio_message(status="failed")]
    twilio_sdk.calls.list.return_value = []

    collector = TwilioUsageCollector(account_sid="AC123", auth_token="tok")
    event = collector.collect("AC123", datetime(2026, 8, 1), datetime(2026, 8, 2))[0]

    assert event.success is False
    assert event.api_action == "message.failed"


def test_twilio_collects_messages_and_calls_sorted(twilio_sdk):
    from collectors.twilio import TwilioUsageCollector

    twilio_sdk.messages.list.return_value = [_twilio_message()]
    twilio_sdk.calls.list.return_value = [_twilio_call()]

    collector = TwilioUsageCollector(account_sid="AC123", auth_token="tok")
    events = collector.collect("AC123", datetime(2026, 8, 1), datetime(2026, 8, 2))

    assert [e.api_action for e in events] == ["message.sent", "call.completed"]
    assert events[0].timestamp <= events[1].timestamp


def test_twilio_requires_credentials(twilio_sdk, monkeypatch):
    import config
    from collectors.twilio import TwilioUsageCollector

    monkeypatch.setattr(config, "TWILIO_ACCOUNT_SID", "", raising=False)
    monkeypatch.setattr(config, "TWILIO_AUTH_TOKEN", "", raising=False)
    with pytest.raises(ValueError, match="Twilio credentials"):
        TwilioUsageCollector()


def test_twilio_empty_window_returns_empty_list(twilio_sdk):
    from collectors.twilio import TwilioUsageCollector

    twilio_sdk.messages.list.return_value = []
    twilio_sdk.calls.list.return_value = []

    collector = TwilioUsageCollector(account_sid="AC123", auth_token="tok")
    assert collector.collect("AC123", datetime(2026, 8, 1), datetime(2026, 8, 2)) == []


# ==========================================================================
# Both collectors honour the BaseCollector contract
# ==========================================================================

def test_collectors_declare_their_platform(stripe_sdk, twilio_sdk):
    from collectors.stripe import StripeEventsCollector
    from collectors.twilio import TwilioUsageCollector

    assert StripeEventsCollector.platform == "stripe"
    assert TwilioUsageCollector.platform == "twilio"


def test_collectors_subclass_base_collector(stripe_sdk, twilio_sdk):
    from collectors.base import BaseCollector
    from collectors.stripe import StripeEventsCollector
    from collectors.twilio import TwilioUsageCollector

    assert issubclass(StripeEventsCollector, BaseCollector)
    assert issubclass(TwilioUsageCollector, BaseCollector)
