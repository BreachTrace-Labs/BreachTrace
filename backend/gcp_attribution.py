"""Conservative matching of GCP audit identity to an operator-associated key ID."""
import hashlib
import hmac
import re

_KEY_NAME = re.compile(r'^//iam\.googleapis\.com/projects/[^/]+/serviceAccounts/([^/]+)/keys/([a-fA-F0-9]{40})$')


def key_digest(key_id: str) -> str:
    return hashlib.sha256(key_id.lower().encode('ascii')).hexdigest()


def event_attribution(event, incident, association):
    if event.platform not in ('gcp', 'firebase') or association is None:
        return None
    raw = event.raw_data if isinstance(event.raw_data, dict) else {}
    auth = raw.get('authenticationInfo')
    if not isinstance(auth, dict):
        return 'unavailable'
    principal = auth.get('principalEmail')
    name = auth.get('serviceAccountKeyName')
    if not isinstance(name, str) or not isinstance(principal, str) or not incident.principal_id:
        return 'unavailable'
    match = _KEY_NAME.fullmatch(name)
    if not match or principal.lower() != incident.principal_id.lower() or match.group(1).lower() != principal.lower():
        return 'unavailable'
    return 'matched' if hmac.compare_digest(key_digest(match.group(2)), association.key_digest) else 'different_key'
