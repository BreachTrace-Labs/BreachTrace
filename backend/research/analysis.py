from __future__ import annotations

from collections import Counter
from math import ceil
from statistics import mean, median, pstdev
from typing import Any


def _numeric_values(runs: list[dict[str, Any]], field: str) -> list[float]:
    values: list[float] = []
    for run in runs:
        value = run.get(field)
        if isinstance(value, (int, float)):
            values.append(float(value))
    return values


def _percentile_nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None

    ordered = sorted(values)
    rank = max(1, ceil((percentile / 100.0) * len(ordered)))
    return ordered[rank - 1]


def _summary_stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "mean": None,
            "median": None,
            "stdev": None,
            "p95": None,
            "min": None,
            "max": None,
        }

    return {
        "count": len(values),
        "mean": mean(values),
        "median": median(values),
        "stdev": 0.0 if len(values) == 1 else pstdev(values),
        "p95": _percentile_nearest_rank(values, 95),
        "min": min(values),
        "max": max(values),
    }


def _severity_distribution(runs: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter()
    for run in runs:
        severity = run.get("overall_severity")
        if isinstance(severity, str) and severity.strip():
            counter[severity.strip().upper()] += 1
    return dict(sorted(counter.items()))


def _impact_category_distribution(runs: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter()
    for run in runs:
        categories = run.get("impact_categories") or []
        if not isinstance(categories, list):
            continue
        for category in categories:
            if isinstance(category, str) and category.strip():
                counter[category.strip()] += 1
    return dict(sorted(counter.items()))


def _group_distribution(runs: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter()
    for run in runs:
        group = run.get("experiment_group")
        if isinstance(group, str) and group.strip():
            counter[group.strip().upper()] += 1
    return dict(sorted(counter.items()))


def _classification_accuracy(runs: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = 0
    correct = 0

    for run in runs:
        if isinstance(run.get("classification_correct"), bool):
            evaluated += 1
            if run["classification_correct"]:
                correct += 1
            continue

        expected_severity = run.get("expected_overall_severity")
        actual_severity = run.get("overall_severity")
        expected_categories = run.get("expected_impact_categories")
        actual_categories = run.get("impact_categories")

        comparisons: list[bool] = []

        if isinstance(expected_severity, str) and isinstance(actual_severity, str):
            comparisons.append(expected_severity.strip().upper() == actual_severity.strip().upper())

        if isinstance(expected_categories, list) and isinstance(actual_categories, list):
            expected = {c.strip() for c in expected_categories if isinstance(c, str) and c.strip()}
            actual = {c.strip() for c in actual_categories if isinstance(c, str) and c.strip()}
            comparisons.append(expected == actual)

        if comparisons:
            evaluated += 1
            if all(comparisons):
                correct += 1

    accuracy = (correct / evaluated) if evaluated else None
    return {
        "evaluated_runs": evaluated,
        "correct_runs": correct,
        "accuracy": accuracy,
    }


def compute_metrics(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute summary statistics over a list of experiment-run dictionaries.

    The function only uses fields that are already present in the supplied run
    dicts. Missing optional fields simply produce empty/None metrics instead of
    forcing a stricter schema than the repo currently has.
    """
    detection_values = _numeric_values(runs, "detection_time_s")
    report_values = _numeric_values(runs, "report_time_s")
    first_use_values = _numeric_values(runs, "first_external_use_s")

    return {
        "total_runs": len(runs),
        "timing": {
            "detection_time_s": _summary_stats(detection_values),
            "report_time_s": _summary_stats(report_values),
            "first_external_use_s": _summary_stats(first_use_values),
        },
        "classification_accuracy": _classification_accuracy(runs),
        "severity_distribution": _severity_distribution(runs),
        "impact_category_distribution": _impact_category_distribution(runs),
        "group_distribution": _group_distribution(runs),
    }
