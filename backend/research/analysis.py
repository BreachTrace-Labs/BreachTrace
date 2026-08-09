# Statistical analysis of experiment results across all 35 runs (12 AWS + 12 GCP + 11 Azure).
# Each run is a metrics dict returned by run_aws/gcp/azure_experiment().
#
# TODO(Yash): run compute_metrics() on Day 7 once all 35 experiment results are recorded.

import statistics


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = int(len(sorted_vals) * 0.95)
    return sorted_vals[min(idx, len(sorted_vals) - 1)]


def compute_metrics(runs: list[dict]) -> dict:
    """Compute summary statistics over a list of ExperimentRun dicts."""
    first_use_times = [r["first_use_time_s"] for r in runs if r.get("first_use_time_s") is not None]
    detection_times = [r["detection_time_s"]  for r in runs if r.get("detection_time_s")  is not None]
    report_times    = [r["report_time_s"]     for r in runs if r.get("report_time_s")     is not None]

    severity_counts: dict[str, int] = {}
    for r in runs:
        sev = r.get("overall_severity") or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    completed = [r for r in runs if r.get("status") == "complete"]

    return {
        "total_runs":              len(runs),
        "completed_runs":          len(completed),
        "first_use_time_median":   statistics.median(first_use_times) if first_use_times else None,
        "first_use_time_p95":      _p95(first_use_times),
        "detection_time_median":   statistics.median(detection_times) if detection_times else None,
        "detection_time_p95":      _p95(detection_times),
        "report_time_median":      statistics.median(report_times)    if report_times    else None,
        "report_time_p95":         _p95(report_times),
        "severity_distribution":   severity_counts,
    }


# =============================================================================
# Cross-platform comparison (S3-S3)
#
# These feed the paper's headline result — "does forensic observability differ
# measurably by platform?" — and the Research page's per-platform latency chart.
#
# Run dicts reach these functions from two sources with DIFFERENT field names:
#
#   1. research/harness.py in-memory results — 'platform', 'first_use_time_s',
#      'overall_severity', 'events_collected'
#   2. GET /research/export (DB-backed) — 'actual_severity', 'first_external_use_s',
#      'event_count', and today NO platform field at all
#
# Rather than force one convention retroactively, every read goes through _first()
# and accepts either spelling. Runs with no platform key are attributed to 'aws',
# matching the default used across the pipeline and schema.
# =============================================================================

DEFAULT_PLATFORM = "aws"

_PLATFORM_KEYS = ("platform",)
_DETECTION_KEYS = ("detection_time_s",)
_REPORT_KEYS = ("report_time_s",)
_FIRST_USE_KEYS = ("first_use_time_s", "first_external_use_s")
_SEVERITY_KEYS = ("overall_severity", "actual_severity")
_EVENT_COUNT_KEYS = ("events_collected", "event_count")


def _first(run: dict, keys: tuple[str, ...], default=None):
    """Return the first non-None value among `keys`, tolerating both schemas."""
    for key in keys:
        value = run.get(key)
        if value is not None:
            return value
    return default


def _numeric(runs: list[dict], keys: tuple[str, ...]) -> list[float]:
    """Collect numeric values for a metric, silently dropping nulls and junk."""
    values: list[float] = []
    for run in runs:
        value = _first(run, keys)
        if value is None or isinstance(value, bool):
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return values


def _summarize(values: list[float]) -> dict:
    """
    Mean/median/p95/min/max for one metric.

    Returns None values rather than 0.0 when there is no data — a platform that
    recorded no timings must not appear in the paper as "0 seconds to detect".
    """
    if not values:
        return {"n": 0, "mean": None, "median": None, "p95": None, "min": None, "max": None}
    return {
        "n": len(values),
        "mean": round(statistics.fmean(values), 2),
        "median": round(statistics.median(values), 2),
        "p95": round(_p95(values), 2),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
    }


def group_by_platform(runs: list[dict]) -> dict[str, list[dict]]:
    """Bucket runs by platform, defaulting missing/blank platform values to 'aws'."""
    grouped: dict[str, list[dict]] = {}
    for run in runs:
        platform = _first(run, _PLATFORM_KEYS, DEFAULT_PLATFORM)
        platform = str(platform).strip().lower() or DEFAULT_PLATFORM
        grouped.setdefault(platform, []).append(run)
    return grouped


def compare_platforms(runs: list[dict]) -> dict:
    """
    Per-platform breakdown of every experiment metric.

    Returns ``{platform: {...}}`` with, for each platform: run/completion counts,
    detection / report / first-use timing summaries, severity distribution and
    event-count statistics. An empty input returns ``{}``.
    """
    result: dict[str, dict] = {}

    for platform, platform_runs in sorted(group_by_platform(runs).items()):
        completed = [r for r in platform_runs if r.get("status") == "complete"]

        severity_counts: dict[str, int] = {}
        for run in platform_runs:
            severity = _first(run, _SEVERITY_KEYS) or "unknown"
            severity = str(severity).upper() if severity != "unknown" else "unknown"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        total = len(platform_runs)
        result[platform] = {
            "total_runs": total,
            "completed_runs": len(completed),
            "completion_rate": round(len(completed) / total, 3) if total else 0.0,
            "detection_time_s": _summarize(_numeric(platform_runs, _DETECTION_KEYS)),
            "report_time_s": _summarize(_numeric(platform_runs, _REPORT_KEYS)),
            "first_use_time_s": _summarize(_numeric(platform_runs, _FIRST_USE_KEYS)),
            "events_collected": _summarize(_numeric(platform_runs, _EVENT_COUNT_KEYS)),
            "severity_distribution": severity_counts,
        }

    return result


def latency_by_platform(runs: list[dict]) -> dict[str, float]:
    """
    Mean detection latency in seconds per platform — the paper's summary table
    and the Research page's grouped bar chart.

    Platforms with no usable timing are omitted entirely rather than reported as
    0.0, so an unprovisioned platform cannot masquerade as an instant one.
    """
    latencies: dict[str, float] = {}

    for platform, platform_runs in group_by_platform(runs).items():
        values = _numeric(platform_runs, _DETECTION_KEYS)
        if values:
            latencies[platform] = round(statistics.fmean(values), 2)

    return latencies
