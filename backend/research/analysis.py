# Statistical analysis of experiment results
# TODO (Yash/Day 6): compute metrics from experiment_runs table.
#
# Metrics to produce:
#   - Median / p95 time-to-first-use across 35 runs
#   - Median / p95 time-to-detection
#   - Median / p95 time-to-report
#   - Classification accuracy (correct / total)
#   - Blast radius severity distribution (pie chart data)


def compute_metrics(runs: list[dict]) -> dict:
    """Compute summary statistics over a list of ExperimentRun dicts."""
    raise NotImplementedError
