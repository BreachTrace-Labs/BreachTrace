"""
Automated experiment runner for Track B (35 pipeline runs).
Orchestrates: push credential → simulate attacker → wait → collect results.
"""

# TODO: Implement the full harness loop
# See WORD.MD Section 4, Day 6 for the complete specification.
#
# The loop:
#   1. create_experiment_key() → (key_id, secret)
#   2. push_fake_credential(key_id, secret) → commit to test repo
#   3. Wait 60s for webhook + CloudTrail
#   4. simulate_attacker_activity(key_id, secret) → 3 API calls
#   5. Wait 120s for CloudTrail delivery + pipeline
#   6. Poll GET /incidents until status='complete'
#   7. Record timing + results to experiment_runs table
#   8. delete_experiment_key(key_id) → revoke
#   9. delete_credential_from_repo()
#  10. Wait 30s, repeat
