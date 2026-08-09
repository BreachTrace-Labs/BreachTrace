"""
Report vocabulary must match the platform the incident happened on.

A GCP report that talks about S3 buckets and `aws iam` commands is worse than
no report: it tells the reader to run commands that do not exist on their
platform. These tests pin the vocabulary and the remediation commands per
platform, and pin the cross-platform wording.

No network is used — the deterministic fallback path is exercised by clearing
GEMINI_API_KEY, and the prompt builder is tested directly.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import config
from normalizer.schema import ForensicEvent
from reporter.gemini import _build_prompt, _resolve_platform, generate_report


def _event(platform: str, api_action: str, event_source: str, **kwargs) -> ForensicEvent:
    return ForensicEvent(
        platform=platform,
        timestamp=datetime.now(timezone.utc),
        api_action=api_action,
        event_source=event_source,
        source_ip="45.33.32.156",
        impact_category=kwargs.pop("impact_category", "reconnaissance"),
        severity_weight=kwargs.pop("severity_weight", 1),
        **kwargs,
    )


@pytest.fixture
def no_gemini(monkeypatch):
    """Force the deterministic fallback path — never calls the API."""
    monkeypatch.setattr(config, "GEMINI_API_KEY", "", raising=False)


def _prompt(platform: str, events: list[ForensicEvent]) -> str:
    return _build_prompt(
        events=events,
        overall_severity="HIGH",
        exposure_duration_seconds=600,
        affected_resources=[],
        source_ips=["45.33.32.156"],
        platform=platform,
    )


# ---------------------------------------------------------------------------
# Platform resolution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "platform, action, source",
    [
        ("gcp", "storage.objects.get", "storage.googleapis.com"),
        ("azure", "Microsoft.Storage/storageAccounts/read", "microsoft.storage"),
        ("aws", "GetObject", "s3.amazonaws.com"),
    ],
)
def test_platform_inferred_from_events(platform, action, source):
    """pipeline.py does not pass `platform` yet — inference keeps reports correct."""
    assert _resolve_platform(None, [_event(platform, action, source)]) == platform


def test_explicit_platform_beats_inference():
    assert _resolve_platform("azure", [_event("gcp", "storage.objects.get", "s.g.c")]) == "azure"


def test_defaults_to_aws_with_no_events():
    assert _resolve_platform(None, []) == "aws"


# ---------------------------------------------------------------------------
# Per-platform vocabulary
# ---------------------------------------------------------------------------

def test_gcp_prompt_uses_gcp_vocabulary_only():
    prompt = _prompt("gcp", [_event("gcp", "storage.objects.get", "storage.googleapis.com")])

    for expected in ("Cloud Storage", "service account", "Cloud Audit Logs", "gcloud"):
        assert expected in prompt

    for forbidden in ("S3 bucket", "EC2 instance", "aws iam delete-access-key"):
        assert forbidden not in prompt


def test_azure_prompt_uses_azure_vocabulary_only():
    prompt = _prompt("azure", [_event("azure", "Microsoft.Storage/storageAccounts/read", "microsoft.storage")])

    for expected in ("storage account", "service principal", "Activity Log", "az ad"):
        assert expected in prompt

    assert "gcloud" not in prompt


def test_aws_prompt_keeps_aws_vocabulary():
    prompt = _prompt("aws", [_event("aws", "GetObject", "s3.amazonaws.com")])

    for expected in ("CloudTrail", "aws iam delete-access-key", "S3"):
        assert expected in prompt


# ---------------------------------------------------------------------------
# Cross-platform incidents
# ---------------------------------------------------------------------------

def test_cross_platform_incident_is_flagged_and_tagged():
    prompt = _prompt(
        "aws",
        [
            _event("aws", "ListBuckets", "s3.amazonaws.com"),
            _event("gcp", "storage.buckets.list", "storage.googleapis.com"),
        ],
    )

    assert "Cross-platform incident" in prompt
    assert "AWS" in prompt and "Google Cloud" in prompt
    # Each event line must say which platform it came from.
    assert "[AWS]" in prompt and "[GCP]" in prompt
    # Rotating one credential must not be presented as full remediation.
    assert "does not remediate the other" in prompt


# ---------------------------------------------------------------------------
# Fallback path
# ---------------------------------------------------------------------------

def test_gcp_fallback_does_not_mention_cloudtrail(no_gemini):
    report = generate_report(
        events=[_event("gcp", "storage.objects.get", "storage.googleapis.com")],
        overall_severity="HIGH",
        exposure_duration_seconds=300,
        affected_resources=[],
        source_ips=[],
        platform="gcp",
    )

    assert "CloudTrail" not in report
    assert "Cloud Audit Logs" in report
    assert "gcloud iam service-accounts keys delete" in report
    assert report.count("☐") >= 3


def test_fallback_infers_platform_when_caller_omits_it(no_gemini):
    """Guards the pre-merge pipeline.py call site, which passes no platform."""
    report = generate_report(
        events=[_event("azure", "Microsoft.Storage/storageAccounts/read", "microsoft.storage")],
        overall_severity="LOW",
        exposure_duration_seconds=30,
        affected_resources=[],
        source_ips=[],
    )

    assert "Activity Log" in report
    assert "az ad" in report


def test_gemini_failure_falls_back_instead_of_raising(monkeypatch):
    """The pipeline must never die because the LLM did."""
    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key", raising=False)

    import reporter.gemini as gemini

    class _Boom:
        def generate_content(self, prompt):
            raise RuntimeError("API unavailable")

    monkeypatch.setattr(gemini, "_get_model", lambda: _Boom())

    report = generate_report(
        events=[_event("aws", "GetObject", "s3.amazonaws.com")],
        overall_severity="HIGH",
        exposure_duration_seconds=10,
        affected_resources=[],
        source_ips=[],
        platform="aws",
    )

    assert "Automated summary" in report
    assert "CloudTrail" in report
