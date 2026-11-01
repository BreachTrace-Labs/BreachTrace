"""
The pipeline must say WHY collection could not run.

Stripe and Twilio import their SDKs lazily inside `__init__` (both are optional
for AWS-only installs), and every collector validates its credentials there too.
So a missing package and a missing API key both raise before a single retry has
happened.

The pipeline used to construct the collector inside the same `try` as
`collect()`, so all three causes were recorded as "<PLATFORM> event collection
failed after retries". That message is actively misleading: it sends whoever
debugs it hunting API credentials for what is a missing `pip install`, and the
stubbed-collector tests never see it because they never exercise construction.

These tests pin the distinction. They are cheap; the afternoon they save is not.
"""

from datetime import datetime, timezone
from unittest import mock

import pytest

import pipeline


@pytest.fixture
def captured_errors(monkeypatch):
    """
    Run the pipeline with the database stubbed out, capturing the error message
    recorded against the incident.
    """
    messages: list[str] = []

    monkeypatch.setattr(pipeline, "SessionLocal", mock.MagicMock())
    monkeypatch.setattr(pipeline, "update_status", lambda *a, **kw: None)
    monkeypatch.setattr(
        pipeline,
        "save_collection_status",
        lambda db, **kw: messages.append(kw["error_message"]),
    )
    return messages


def run_with_collector(collector_cls, monkeypatch) -> None:
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, "stripe", collector_cls)
    pipeline.run_collection_pipeline(
        "incident-under-test",
        "sk_test_leaked_key",
        datetime.now(tz=timezone.utc),
        platform="stripe",
    )


def test_missing_sdk_names_the_package_not_a_retry_failure(captured_errors, monkeypatch):
    class SdkNotInstalled:
        def __init__(self):
            raise ImportError("No module named 'stripe'")

    run_with_collector(SdkNotInstalled, monkeypatch)

    message = captured_errors[0]
    assert "SDK is not installed" in message
    assert "pip install" in message
    # The failure mode this test exists to prevent.
    assert "after retries" not in message


def test_missing_credentials_surface_the_real_reason(captured_errors, monkeypatch):
    class NoApiKey:
        def __init__(self):
            raise ValueError("No Stripe API key available: set STRIPE_API_KEY")

    run_with_collector(NoApiKey, monkeypatch)

    message = captured_errors[0]
    assert "could not be initialised" in message
    assert "STRIPE_API_KEY" in message
    assert "after retries" not in message


def test_initialisation_error_is_truncated(captured_errors, monkeypatch):
    """
    The message reaches the DB column and the UI, and an SDK is free to raise
    with an arbitrarily large payload attached.
    """

    class NoisyFailure:
        def __init__(self):
            raise RuntimeError("x" * 5000)

    run_with_collector(NoisyFailure, monkeypatch)

    message = captured_errors[0]
    assert len(message) < 400
    assert "RuntimeError" in message


def test_genuine_collection_failure_still_reports_retries(captured_errors, monkeypatch):
    """The original message is correct for its original cause — keep it."""

    class CollectRaises:
        def collect(self, **kwargs):
            raise TimeoutError("upstream unavailable")

    run_with_collector(CollectRaises, monkeypatch)

    assert captured_errors[0] == "STRIPE event collection failed after retries"


def test_unsupported_platform_is_unchanged(captured_errors, monkeypatch):
    pipeline.run_collection_pipeline(
        "incident-under-test",
        "whatever",
        datetime.now(tz=timezone.utc),
        platform="not_a_platform",
    )

    assert captured_errors[0] == "Unsupported platform: not_a_platform"
