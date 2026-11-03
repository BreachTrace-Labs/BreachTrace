from research.model_benchmark import summarize


def test_failed_runs_count_in_grounding_and_latency():
    rows = [dict(latency_s=1, valid_json=True, grounded=True, fact_coverage=.8),
            dict(latency_s=180, valid_json=False, grounded=False, fact_coverage=0, error_type="Timeout")]
    summary = summarize(rows)
    assert summary["grounding_pass_rate"] == .5
    assert summary["mean_fact_coverage"] == .4
    assert summary["p95_latency_s"] == 180
    assert summary["failures"] == 1


def test_empty_benchmark_is_not_reported_as_perfect():
    assert summarize([])["grounding_pass_rate"] is None
