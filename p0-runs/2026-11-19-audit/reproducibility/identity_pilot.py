"""Offline development-only identity mechanism check; no provider access."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / 'backend'))
from gcp_attribution import event_attribution, key_digest

email = 'svc@example.invalid'
target, sibling = 'a' * 40, 'b' * 40
incident = SimpleNamespace(principal_id=email)
association = SimpleNamespace(key_digest=key_digest(target))
observations = []
for case, key in [('target', target), ('sibling', sibling), ('missing', None)]:
    auth = {'principalEmail': email}
    if key:
        auth['serviceAccountKeyName'] = f'//iam.googleapis.com/projects/demo/serviceAccounts/{email}/keys/{key}'
    event = SimpleNamespace(platform='gcp', raw_data={'authenticationInfo': auth})
    actual = event_attribution(event, incident, association)
    methods = {'frozen_identity_function': {'matched': 'target', 'different_key': 'other', 'unavailable': 'unknown', None: 'unknown'}[actual],
               'always_abstain': 'unknown', 'principal_time': 'target',
               'native_key_field': 'target' if key == target else 'other' if key else 'unknown'}
    observations.append({'case': case, 'fixture_truth': case, 'methods': methods})
print(json.dumps(observations, indent=2))
