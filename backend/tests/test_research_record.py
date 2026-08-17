"""
Tests for POST /research/record (B2).

This endpoint is the reason the Research page has data at all — nothing in the
codebase wrote an ExperimentRun row before it existed, so /export and
/platforms always returned empty against a live backend.

Tested at the Pydantic/helper level, matching the rest of the suite: no
TestClient, no database. The validation logic is where the interesting failures
live, and all of it is reachable without a session.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from db.models import VALID_PLATFORMS
from routers.research import ExperimentRunIn, ExperimentRunOut, _next_run_number


# ==========================================================================
# Field-name tolerance — the harness and the DB disagree
# ==========================================================================

def test_accepts_harness_field_spellings():
    """
    The harness emits `first_use_time_s` and `api_calls`; the DB columns are
    `first_external_use_s` and `api_calls_made`. analysis.py already reads
    either, so the recorder must not be stricter than the analysis it feeds.
    """
    run = ExperimentRunIn(
        platform="gcp",
        first_use_time_s=14.2,
        api_calls=["storage.buckets.list", "compute.instances.insert"],
    )

    assert run.first_external_use_s == 14.2
    assert run.api_calls_made == ["storage.buckets.list", "compute.instances.insert"]


def test_accepts_canonical_db_spellings():
    run = ExperimentRunIn(
        platform="aws",
        first_external_use_s=9.5,
        api_calls_made=["ListBuckets"],
    )
    assert run.first_external_use_s == 9.5
    assert run.api_calls_made == ["ListBuckets"]


# ==========================================================================
# Platform validation — no CHECK constraint backs this column
# ==========================================================================

def test_platform_is_normalised():
    assert ExperimentRunIn(platform=" GCP ").platform == "gcp"
    assert ExperimentRunIn(platform="Azure").platform == "azure"


def test_platform_defaults_to_aws():
    assert ExperimentRunIn().platform == "aws"


def test_unknown_platform_is_rejected():
    """
    experiment_runs.platform has no CHECK constraint, so a typo would be
    persisted happily and appear as a phantom bar in the paper's headline
    figure. Validation here is the only guard.
    """
    with pytest.raises(ValidationError, match="Unknown platform"):
        ExperimentRunIn(platform="gcpp")


@pytest.mark.parametrize("platform", VALID_PLATFORMS)
def test_every_valid_platform_is_accepted(platform):
    """Guards against the validator and VALID_PLATFORMS drifting apart."""
    assert ExperimentRunIn(platform=platform).platform == platform


# ==========================================================================
# Severity normalisation
# ==========================================================================

@pytest.mark.parametrize("given,expected", [
    ("high", "HIGH"),
    ("High", "HIGH"),
    ("CRITICAL", "CRITICAL"),
    ("  low  ", "LOW"),
])
def test_severity_is_uppercased(given, expected):
    """
    compare_platforms() and /incidents/stats both uppercase. Without matching
    here, one campaign could produce both 'High' and 'HIGH' buckets in the
    severity distribution.
    """
    assert ExperimentRunIn(overall_severity=given).overall_severity == expected


def test_missing_severity_stays_none():
    assert ExperimentRunIn().overall_severity is None
    assert ExperimentRunIn(overall_severity="").overall_severity is None


# ==========================================================================
# Latency precision
# ==========================================================================

def test_float_latencies_survive():
    """
    The columns were Integer until the d5e6f7a8b9c0 migration; posting 14.2
    raised. Sub-second precision is the point of that migration.
    """
    run = ExperimentRunIn(detection_time_s=14.2, report_time_s=38.7)
    assert run.detection_time_s == 14.2
    assert run.report_time_s == 38.7


def test_integer_latencies_still_accepted():
    run = ExperimentRunIn(detection_time_s=14, report_time_s=38)
    assert run.detection_time_s == 14.0


# ==========================================================================
# Run numbering
# ==========================================================================

def test_next_run_number_starts_at_one():
    assert _next_run_number([]) == 1


def test_next_run_number_increments_from_max():
    assert _next_run_number([1, 5, 3]) == 6


def test_next_run_number_ignores_nulls():
    """Existing rows may have a null run_number; they must not break numbering."""
    assert _next_run_number([None, 2, None]) == 3


def test_next_run_number_handles_all_nulls():
    assert _next_run_number([None, None]) == 1


# ==========================================================================
# Round trip into the response model
# ==========================================================================

class _FakeRun:
    """Stands in for a persisted ExperimentRun row."""

    def __init__(self, **overrides):
        self.id = "run-1"
        self.detection_time_s = 14.2
        self.report_time_s = 38.7
        self.api_calls_made = ["ListBuckets"]
        self.overall_severity = "HIGH"
        self.platform = "gcp"
        self.run_number = 7
        self.experiment_group = "B"
        self.first_external_use_s = 31.4
        self.external_use_detected = True
        self.created_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.__dict__.update(overrides)


def test_recorded_run_serialises_into_the_export_shape():
    """
    What /record returns must match what /export serves, so a caller can verify
    a write without a second request.
    """
    run = _FakeRun()
    out = ExperimentRunOut(
        run_id=run.id,
        access_key_id=None,
        detection_time_s=run.detection_time_s,
        report_time_s=run.report_time_s,
        api_calls=run.api_calls_made,
        expected_severity=None,
        actual_severity=run.overall_severity,
        status="complete",
        created_at=run.created_at,
        platform=run.platform,
        run_number=run.run_number,
        experiment_group=run.experiment_group,
        first_external_use_s=run.first_external_use_s,
        external_use_detected=run.external_use_detected,
        event_count=5,
    )

    assert out.platform == "gcp"
    assert out.detection_time_s == 14.2
    assert out.first_external_use_s == 31.4
    assert out.event_count == 5


def test_recorded_runs_feed_compare_platforms():
    """End-to-end shape check against the function the chart actually calls."""
    from research.analysis import compare_platforms

    rows = [
        ExperimentRunOut(
            run_id=f"run-{i}",
            access_key_id=None,
            detection_time_s=10.0 + i,
            report_time_s=40.0,
            api_calls=[],
            expected_severity=None,
            actual_severity="HIGH",
            status="complete",
            created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            platform=platform,
        ).model_dump()
        for i, platform in enumerate(["aws", "gcp", "stripe"])
    ]

    result = compare_platforms(rows)
    assert set(result) == {"aws", "gcp", "stripe"}
    assert result["aws"]["detection_time_s"]["mean"] == 10.0
    assert result["stripe"]["detection_time_s"]["mean"] == 12.0
