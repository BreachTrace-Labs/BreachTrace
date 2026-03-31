from research.analysis import compute_metrics


def test_compute_metrics_summarizes_timing_fields():
    runs = [
        {
            "run_number": 1,
            "experiment_group": "A",
            "detection_time_s": 10,
            "report_time_s": 40,
            "first_external_use_s": 5,
            "overall_severity": "LOW",
            "impact_categories": ["reconnaissance"],
        },
        {
            "run_number": 2,
            "experiment_group": "B",
            "detection_time_s": 20,
            "report_time_s": 60,
            "first_external_use_s": 15,
            "overall_severity": "CRITICAL",
            "impact_categories": ["exfiltration", "reconnaissance"],
        },
        {
            "run_number": 3,
            "experiment_group": "C",
            "detection_time_s": 30,
            "report_time_s": 80,
            "first_external_use_s": 25,
            "overall_severity": "LOW",
            "impact_categories": ["reconnaissance"],
        },
    ]

    metrics = compute_metrics(runs)

    assert metrics["total_runs"] == 3
    assert metrics["timing"]["detection_time_s"] == {
        "count": 3,
        "mean": 20.0,
        "median": 20.0,
        "stdev": 8.16496580927726,
        "p95": 30.0,
        "min": 10.0,
        "max": 30.0,
    }
    assert metrics["timing"]["report_time_s"]["median"] == 60.0
    assert metrics["timing"]["first_external_use_s"]["p95"] == 25.0
    assert metrics["severity_distribution"] == {"CRITICAL": 1, "LOW": 2}
    assert metrics["impact_category_distribution"] == {
        "exfiltration": 1,
        "reconnaissance": 3,
    }
    assert metrics["group_distribution"] == {"A": 1, "B": 1, "C": 1}


def test_compute_metrics_uses_explicit_classification_correct_when_present():
    runs = [
        {"classification_correct": True},
        {"classification_correct": False},
        {"classification_correct": True},
    ]

    metrics = compute_metrics(runs)

    assert metrics["classification_accuracy"] == {
        "evaluated_runs": 3,
        "correct_runs": 2,
        "accuracy": 2 / 3,
    }


def test_compute_metrics_falls_back_to_expected_fields_for_accuracy():
    runs = [
        {
            "expected_overall_severity": "low",
            "overall_severity": "LOW",
            "expected_impact_categories": ["reconnaissance"],
            "impact_categories": ["reconnaissance"],
        },
        {
            "expected_overall_severity": "critical",
            "overall_severity": "HIGH",
            "expected_impact_categories": ["exfiltration"],
            "impact_categories": ["exfiltration"],
        },
    ]

    metrics = compute_metrics(runs)

    assert metrics["classification_accuracy"] == {
        "evaluated_runs": 2,
        "correct_runs": 1,
        "accuracy": 0.5,
    }


def test_compute_metrics_handles_missing_optional_fields():
    metrics = compute_metrics([{"run_number": 1}, {"run_number": 2}])

    assert metrics["timing"]["detection_time_s"] == {
        "count": 0,
        "mean": None,
        "median": None,
        "stdev": None,
        "p95": None,
        "min": None,
        "max": None,
    }
    assert metrics["classification_accuracy"] == {
        "evaluated_runs": 0,
        "correct_runs": 0,
        "accuracy": None,
    }
    assert metrics["severity_distribution"] == {}
    assert metrics["impact_category_distribution"] == {}
    assert metrics["group_distribution"] == {}
