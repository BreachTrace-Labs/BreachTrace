"""
API contract tests (L4).

The frontend reads these response shapes directly. A field that silently stops
being served does not fail the backend — it renders as `undefined` in the UI,
which for `forensic_tier` means a Tier-2 incident displays an empty timeline
and reads as "nothing happened". That is the exact false reassurance the whole
project exists to prevent, so the contract is pinned here.

These test the Pydantic response models, not live HTTP, so no database is
needed.
"""

from datetime import datetime, timezone

import pytest

from routers.incidents import IncidentDetailOut, IncidentSummaryOut, _derive_platform
from routers.research import ExperimentRunOut


class _FakeIncident:
    """Stands in for an IncidentRecord ORM row."""

    def __init__(self, **overrides):
        self.incident_id = "inc-1"
        self.credential_type = "aws_access_key"
        self.credential_hint = "AKIA****MPLE"
        self.access_key_id = "AKIAIOSFODNN7EXAMPLE"
        self.repo_url = "https://github.com/acme/app"
        self.commit_hash = "abc123"
        self.exposure_start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.exposure_end = None
        self.status = "complete"
        self.overall_severity = 3
        self.gdpr_flag = False
        self.created_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.platform = "aws"
        self.principal_id = None
        self.gcp_project_id = None
        self.azure_tenant_id = None
        self.azure_subscription_id = None
        self.forensic_tier = 1
        self.unavailable_reason = None
        self.events = []
        self.report_text = None
        self.remediation_steps = []
        self.financial_impact = None
        self.__dict__.update(overrides)


# ==========================================================================
# Forensic tier on the API
# ==========================================================================

def test_summary_exposes_forensic_tier():
    """
    Must be on the LIST response, not only the detail one: the dashboard has to
    label Tier-2 rows without fetching every incident individually.
    """
    out = IncidentSummaryOut.model_validate(_FakeIncident())
    assert out.forensic_tier == 1
    assert out.unavailable_reason is None


def test_summary_exposes_tier_two_reason():
    incident = _FakeIncident(
        credential_type="github_pat",
        access_key_id=None,
        forensic_tier=2,
        unavailable_reason="GitHub exposes per-token audit logs only to Enterprise organisations.",
    )
    out = IncidentSummaryOut.model_validate(incident)

    assert out.forensic_tier == 2
    assert "Enterprise" in out.unavailable_reason


def test_forensic_tier_defaults_to_one_for_legacy_rows():
    """Rows created before the column existed must not read as Tier 2."""
    incident = _FakeIncident()
    del incident.forensic_tier
    assert IncidentSummaryOut.model_validate(incident).forensic_tier == 1


def test_detail_inherits_tier_fields():
    out = IncidentDetailOut.model_validate(
        _FakeIncident(forensic_tier=2, unavailable_reason="no audit API")
    )
    assert out.forensic_tier == 2
    assert out.unavailable_reason == "no audit API"


def test_severity_int_coerced_to_label():
    assert IncidentSummaryOut.model_validate(_FakeIncident(overall_severity=4)).overall_severity == "CRITICAL"


def test_tier_two_severity_may_be_null():
    """
    We genuinely do not know a Tier-2 blast radius. Defaulting to LOW would be
    a fabrication, so null must survive serialisation.
    """
    out = IncidentSummaryOut.model_validate(
        _FakeIncident(forensic_tier=2, overall_severity=None)
    )
    assert out.overall_severity is None


# ==========================================================================
# Platform derivation on the API
# ==========================================================================

@pytest.mark.parametrize(
    "credential_type,expected",
    [
        ("aws_access_key", "aws"),
        ("gcp_service_account", "gcp"),
        ("firebase_service_account", "gcp"),
        ("azure_service_principal", "azure"),
        ("stripe_secret_key", "stripe"),
        ("twilio_account_sid", "twilio"),
        ("github_pat", "github"),
        ("db_connection_string", "db"),
    ],
)
def test_api_derives_platform_for_every_credential_type(credential_type, expected):
    assert _derive_platform(_FakeIncident(credential_type=credential_type)) == expected


def test_api_platform_falls_back_to_aws():
    assert _derive_platform(_FakeIncident(credential_type="unknown_thing")) == "aws"


# ==========================================================================
# Research export — the platform chart's data source
# ==========================================================================

class _FakeRun:
    def __init__(self, **overrides):
        self.id = "run-1"
        self.detection_time_s = 12
        self.report_time_s = 40
        self.api_calls = []
        self.created_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.__dict__.update(overrides)


def test_research_export_carries_platform():
    """
    Before this, /research/export served no platform field at all, so the
    per-platform chart had literally no data source.
    """
    out = ExperimentRunOut.model_validate(
        _FakeRun(
            access_key_id=None,
            expected_severity=None,
            actual_severity="HIGH",
            status="complete",
            platform="gcp",
            run_number=7,
            experiment_group="B",
            first_external_use_s=31,
            external_use_detected=True,
            event_count=5,
        )
    )

    assert out.platform == "gcp"
    assert out.first_external_use_s == 31
    assert out.event_count == 5
    assert out.external_use_detected is True


def test_research_export_platform_defaults_to_aws():
    """The AWS harness path predates the field; those runs are still real data."""
    out = ExperimentRunOut.model_validate(
        _FakeRun(
            access_key_id="AKIA...",
            expected_severity=None,
            actual_severity=None,
            status=None,
        )
    )
    assert out.platform == "aws"


def test_export_fields_feed_compare_platforms():
    """
    End-to-end shape check: what the endpoint serves must be directly consumable
    by compare_platforms(), which is what the chart calls.
    """
    from research.analysis import compare_platforms

    rows = [
        ExperimentRunOut.model_validate(
            _FakeRun(
                id=f"run-{i}",
                access_key_id=None,
                expected_severity=None,
                actual_severity="HIGH",
                status="complete",
                platform=platform,
                detection_time_s=10 + i,
            )
        ).model_dump()
        for i, platform in enumerate(["aws", "gcp", "azure"])
    ]

    result = compare_platforms(rows)
    assert set(result) == {"aws", "gcp", "azure"}
    assert result["aws"]["detection_time_s"]["mean"] == 10.0
