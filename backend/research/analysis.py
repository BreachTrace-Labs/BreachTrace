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
    detection_times = [r["detection_time_s"] for r in runs if r.get("detection_time_s") is not None]
    report_times    = [r["report_time_s"]    for r in runs if r.get("report_time_s")    is not None]

    severity_counts: dict[str, int] = {}
    for r in runs:
        sev = r.get("overall_severity") or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    completed = [r for r in runs if r.get("status") == "complete"]

    return {
        "total_runs":            len(runs),
        "completed_runs":        len(completed),
        "detection_time_median": statistics.median(detection_times) if detection_times else None,
        "detection_time_p95":    _p95(detection_times),
        "report_time_median":    statistics.median(report_times)    if report_times    else None,
        "report_time_p95":       _p95(report_times),
        "severity_distribution": severity_counts,
    }
