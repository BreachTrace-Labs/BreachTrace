"""Conservative, read-only grouping of GCP audit records by explicit identifiers."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
import re

from normalizer.time_window import utc

_PROJECT = re.compile(r'^projects/([^/]+)/logs/')
_INVOCATION = re.compile(r'(?i)(?:^|[\s(;,])invocation-id[=/]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=$|[\s);,])')


def correlate_gcp_records(events):
    """Return explicit-evidence groups, never modify or collapse raw events.

    Provider operation identifiers and client-supplied invocation identifiers
    are reported separately; neither establishes key use or malicious intent.
    """
    records = [event for event in events if event.platform == 'gcp']
    candidates = defaultdict(list)
    for event in records:
        raw = event.raw_data if isinstance(event.raw_data, dict) else {}
        meta = raw.get('_gcp_log_entry')
        if not isinstance(meta, dict):
            continue
        log_name = meta.get('log_name')
        project_match = _PROJECT.match(log_name) if isinstance(log_name, str) else None
        principal = getattr(event, 'principal_id', None)
        if not project_match or not isinstance(principal, str) or not principal:
            continue
        scope = (project_match.group(1), principal.lower())
        operation = meta.get('operation')
        operation = operation if isinstance(operation, dict) else {}
        operation_id, producer = operation.get('id'), operation.get('producer')
        if isinstance(operation_id, str) and operation_id and isinstance(producer, str) and producer:
            candidates[('provider_operation', *scope, producer, operation_id)].append(event)
        elif not operation_id and isinstance(event.user_agent, str) and 'gcloud' in event.user_agent.lower():
            invocation = _INVOCATION.search(event.user_agent)
            if invocation:
                candidates[('client_invocation', *scope, invocation.group(1).lower())].append(event)

    groups = []
    for key, members in candidates.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda event: (utc(event.timestamp), event.event_id))
        if key[0] == 'client_invocation' and utc(members[-1].timestamp) - utc(members[0].timestamp) > timedelta(hours=24):
            continue
        actions = Counter(event.api_action for event in members)
        groups.append({
            'kind': key[0],
            'confidence': 'high' if key[0] == 'provider_operation' else 'medium',
            'record_count': len(members),
            'successful_count': sum(event.success is True for event in members),
            'failed_count': sum(event.success is False for event in members),
            'first_seen': utc(members[0].timestamp),
            'last_seen': utc(members[-1].timestamp),
            'actions': [{'action': action, 'count': count} for action, count in sorted(actions.items())],
            'event_ids': [event.event_id for event in members],
        })
    groups.sort(key=lambda group: (group['first_seen'], group['event_ids'][0]))
    grouped_count = sum(group['record_count'] for group in groups)
    return {'raw_record_count': len(records), 'group_count': len(groups),
            'grouped_record_count': grouped_count, 'ungrouped_record_count': len(records) - grouped_count,
            'groups': groups}
