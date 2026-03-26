# Research experiment harness
# TODO (Yash/Day 6): implement automated 35-run experiment loop.
#
# Each run:
#   1. Commit a test AWS key to the public test repo via GitHub API
#   2. Record exposure_start
#   3. Make controlled API calls from a second device
#   4. Wait for BreachTrace to detect → collect → classify → report
#   5. Record time_to_detection, time_to_report, classification result
#   6. Revoke the key
#   7. Persist ExperimentRun row to DB


def run_experiment(run_number: int) -> dict:
    """Execute one full experiment run. Returns a result dict."""
    raise NotImplementedError
