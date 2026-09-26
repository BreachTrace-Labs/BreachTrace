"""
Tests for the cross-platform experiment statistics (S3-S3).

These functions produce the paper's headline comparison, so the failure modes
that matter most are the quiet ones: a platform with no data reported as "0
seconds", or runs silently dropped because the export endpoint spells a field
differently from the harness.
"""

import pytest

from research.analysis import (
    compare_platforms,
    compute_metrics,
    group_by_platform,
    latency_by_platform,
)


def _run(platform=None, detection=None, report=None, severity=None,
         status="complete", events=None, first_use=None, **extra):
    run = {"status": status}
    if platform is not None:
        run["platform"] = platform
    if detection is not None:
        run["detection_time_s"] = detection
    if report is not None:
        run["report_time_s"] = report
    if severity is not None:
        run["overall_severity"] = severity
    if events is not None:
        run["events_collected"] = events
    if first_use is not None:
        run["first_use_time_s"] = first_use
    run.update(extra)
    return run


# ==========================================================================
# Grouping
# ==========================================================================

def test_groups_runs_by_platform():
    runs = [_run("aws"), _run("gcp"), _run("aws"), _run("azure")]
    grouped = group_by_platform(runs)
    assert {k: len(v) for k, v in grouped.items()} == {"aws": 2, "gcp": 1, "azure": 1}


def test_runs_without_platform_default_to_aws():
    """
    The AWS harness path predates the platform field and emits none. Those runs
    are real data and must not be dropped or bucketed under 'unknown'.
    """
    assert list(group_by_platform([_run(), _run()])) == ["aws"]


def test_platform_matching_is_case_insensitive():
    grouped = group_by_platform([_run("AWS"), _run("aws"), _run(" Gcp ")])
    assert {k: len(v) for k, v in grouped.items()} == {"aws": 2, "gcp": 1}


# ==========================================================================
# compare_platforms
# ==========================================================================

def test_empty_input_returns_empty_dict():
    assert compare_platforms([]) == {}
    assert latency_by_platform([]) == {}


def test_single_platform_is_handled():
    result = compare_platforms([_run("aws", detection=10), _run("aws", detection=20)])
    assert set(result) == {"aws"}
    assert result["aws"]["detection_time_s"]["mean"] == 15.0


def test_per_platform_timing_summary():
    runs = [
        _run("aws", detection=10, report=40),
        _run("aws", detection=20, report=60),
        _run("gcp", detection=30, report=90),
    ]
    result = compare_platforms(runs)

    assert result["aws"]["detection_time_s"]["mean"] == 15.0
    assert result["aws"]["detection_time_s"]["median"] == 15.0
    assert result["aws"]["detection_time_s"]["n"] == 2
    assert result["aws"]["report_time_s"]["mean"] == 50.0
    assert result["gcp"]["detection_time_s"]["mean"] == 30.0
    assert result["gcp"]["detection_time_s"]["min"] == 30.0


def test_missing_timings_report_none_not_zero():
    """
    A platform that recorded no timings must never appear in the paper as having
    detected in 0 seconds. This is the most damaging possible silent failure.
    """
    result = compare_platforms([_run("azure", detection=None)])
    summary = result["azure"]["detection_time_s"]
    assert summary["mean"] is None
    assert summary["median"] is None
    assert summary["n"] == 0


def test_severity_distribution_per_platform():
    runs = [
        _run("aws", severity="LOW"),
        _run("aws", severity="LOW"),
        _run("aws", severity="CRITICAL"),
        _run("gcp", severity="HIGH"),
    ]
    result = compare_platforms(runs)
    assert result["aws"]["severity_distribution"] == {"LOW": 2, "CRITICAL": 1}
    assert result["gcp"]["severity_distribution"] == {"HIGH": 1}


def test_severity_casing_is_normalised():
    """Harness writes 'Critical', the DB writes 'CRITICAL' — one bucket, not two."""
    result = compare_platforms([_run("aws", severity="Critical"), _run("aws", severity="CRITICAL")])
    assert result["aws"]["severity_distribution"] == {"CRITICAL": 2}


def test_runs_without_severity_bucket_as_unknown():
    result = compare_platforms([_run("aws")])
    assert result["aws"]["severity_distribution"] == {"unknown": 1}


def test_completion_rate():
    runs = [
        _run("aws", status="complete"),
        _run("aws", status="complete"),
        _run("aws", status="failed"),
        _run("aws", status="failed"),
    ]
    result = compare_platforms(runs)
    assert result["aws"]["total_runs"] == 4
    assert result["aws"]["completed_runs"] == 2
    assert result["aws"]["completion_rate"] == 0.5


def test_event_count_statistics():
    result = compare_platforms([_run("gcp", events=3), _run("gcp", events=7)])
    assert result["gcp"]["events_collected"]["mean"] == 5.0
    assert result["gcp"]["events_collected"]["max"] == 7.0


# ==========================================================================
# Schema tolerance — the export endpoint and the harness disagree on names
# ==========================================================================

def test_accepts_export_endpoint_severity_field():
    """GET /research/export serialises severity as 'actual_severity'."""
    result = compare_platforms([{"platform": "aws", "actual_severity": "HIGH", "status": "complete"}])
    assert result["aws"]["severity_distribution"] == {"HIGH": 1}


def test_accepts_db_first_use_field_name():
    """The DB column is 'first_external_use_s'; the harness emits 'first_use_time_s'."""
    from_db = compare_platforms([{"platform": "aws", "first_external_use_s": 12}])
    from_harness = compare_platforms([{"platform": "aws", "first_use_time_s": 12}])
    assert from_db["aws"]["first_use_time_s"]["mean"] == 12.0
    assert from_harness["aws"]["first_use_time_s"]["mean"] == 12.0


def test_accepts_db_event_count_field_name():
    result = compare_platforms([{"platform": "gcp", "event_count": 4}])
    assert result["gcp"]["events_collected"]["mean"] == 4.0


def test_non_numeric_timings_are_ignored_not_fatal():
    """Bad rows must not take down the whole analysis run."""
    runs = [_run("aws", detection=10), _run("aws", detection="n/a"), _run("aws", detection=None)]
    result = compare_platforms(runs)
    assert result["aws"]["detection_time_s"]["n"] == 1
    assert result["aws"]["detection_time_s"]["mean"] == 10.0


def test_booleans_are_not_counted_as_numbers():
    result = compare_platforms([{"platform": "aws", "detection_time_s": True}])
    assert result["aws"]["detection_time_s"]["n"] == 0


# ==========================================================================
# latency_by_platform — the paper table
# ==========================================================================

def test_latency_by_platform_returns_mean_per_platform():
    runs = [
        _run("aws", detection=10), _run("aws", detection=20),
        _run("gcp", detection=30),
        _run("azure", detection=40), _run("azure", detection=60),
    ]
    assert latency_by_platform(runs) == {"aws": 15.0, "gcp": 30.0, "azure": 50.0}


def test_latency_omits_platforms_with_no_timing_data():
    """
    An unprovisioned platform must be absent from the table, not present at 0.0.
    Absent reads as "not measured"; 0.0 reads as "instantaneous".
    """
    result = latency_by_platform([_run("aws", detection=10), _run("azure", detection=None)])
    assert result == {"aws": 10.0}
    assert "azure" not in result


# ==========================================================================
# Existing aggregate metrics must keep working
# ==========================================================================

def test_compute_metrics_still_works_on_mixed_platform_runs():
    runs = [_run("aws", detection=10, report=40), _run("gcp", detection=20, report=60)]
    metrics = compute_metrics(runs)
    assert metrics["total_runs"] == 2
    assert metrics["completed_runs"] == 2
    assert metrics["detection_time_median"] == 15.0


def test_compute_metrics_on_empty_input_does_not_crash():
    metrics = compute_metrics([])
    assert metrics["total_runs"] == 0
    assert metrics["detection_time_median"] is None
