"""
Full E2E pipeline integration test.
Calls POST /test/simulate, waits, asserts status='complete'.
"""

# TODO: Implement after all pipeline stages are wired together.
# - POST /test/simulate with a fake diff containing an AWS key
# - Poll GET /incidents/{id} every 10s, max 90s
# - Assert status='complete' and events are classified
