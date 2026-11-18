"""Conservative matching of GCP audit identity to an operator-associated key ID."""
import hashlib
import hmac
import re

_KEY_NAME = re.compile(r'^//iam\.googleapis\.com/projects/[^/]+/serviceAccounts/([^/]+)/keys/([a-fA-F0-9]{40})$')


def key_digest(key_id: str) -> str:
    return hashlib.sha256(key_id.lower().encode('ascii')).hexdigest()


def record_detected_key(db, incident, match, *, simulated=False):
    """Associate metadata from one structured document in the incident transaction."""
    if not getattr(match, 'structured_key', False):
        return
    from db.models import GCPKeyAssociation
    incident.gcp_project_id = match.project_id
    db.add(GCPKeyAssociation(incident_id=incident.incident_id,
                             key_digest=key_digest(match.private_key_id),
                             key_hint=match.private_key_id[:4] + '…' + match.private_key_id[-4:],
                             source='detected_in_simulation' if simulated else 'detected_in_commit'))


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
