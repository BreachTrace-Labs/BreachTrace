# Full end-to-end pipeline integration test
# TODO (Ritwik/Day 5): implement against a live test environment.
#
# Flow:
#   1. POST /test/simulate → creates a test incident with a fake AWS key
#   2. Poll GET /incidents/{id} until status == 'complete'
#   3. Assert: events list non-empty, overall_severity set, report_text non-empty

import pytest


@pytest.mark.integration
def test_full_pipeline_smoke():
    pytest.skip("Integration test — run manually with live AWS credentials")
