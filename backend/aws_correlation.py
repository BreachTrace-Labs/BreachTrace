"""Conservative relationships between AWS CloudTrail records."""
from collections import Counter, defaultdict
from bisect import bisect_left, bisect_right
from datetime import timedelta
import json
from urllib.parse import unquote, urlsplit

from normalizer.time_window import utc


def _record(event):
    raw = event.raw_data if isinstance(event.raw_data, dict) else {}
    nested = raw.get('CloudTrailEvent')
    if isinstance(nested, str):
        try:
            nested = json.loads(nested)
        except (ValueError, TypeError):
            return {}
    return nested if isinstance(nested, dict) else raw


def _source(value):
    if not isinstance(value, str) or not value:
        return None
    if value.startswith('arn:'):
        return None
    if value.startswith('s3://'):
        parsed = urlsplit(value)
        value = parsed.netloc + unquote(parsed.path)
    else:
        value = unquote(value.split('?', 1)[0]).lstrip('/')
    bucket, sep, key = value.partition('/')
    return (bucket, key) if sep and bucket and key else None


def correlate_aws_records(events):
    """Identify unambiguous likely copy-related reads without changing records."""
    records = [event for event in events if event.platform == 'aws']
    reads, copies = [], []
    for event in records:
        if event.success is not True or event.api_action not in ('GetObject', 'CopyObject'):
            continue
        raw = _record(event)
        identity = raw.get('userIdentity') or {}
        params = raw.get('requestParameters') or {}
        if not isinstance(identity, dict) or not isinstance(params, dict):
            continue
        key_id, ip = identity.get('accessKeyId'), raw.get('sourceIPAddress') or event.source_ip
        if not isinstance(key_id, str) or not key_id or not isinstance(ip, str) or not ip:
            continue
        if event.api_action == 'GetObject':
            bucket, name = params.get('bucketName'), params.get('key')
            obj = (bucket, name) if isinstance(bucket, str) and bucket and isinstance(name, str) and name else None
        else:
            obj = _source(params.get('copySource') or params.get('x-amz-copy-source'))
        if obj:
            (reads if event.api_action == 'GetObject' else copies).append((event, key_id, ip, obj))

    def indexed(items):
        result = defaultdict(list)
        for event, key_id, ip, obj in items:
            result[(key_id, ip, obj)].append((utc(event.timestamp), event.event_id, event))
        output = {}
        for key, rows in result.items():
            rows.sort(key=lambda row: (row[0], row[1]))
            output[key] = (rows, [row[0] for row in rows])
        return output

    read_index, copy_index = indexed(reads), indexed(copies)
    def nearby(index, when):
        rows, times = index
        left = bisect_left(times, when - timedelta(seconds=3))
        right = bisect_right(times, when + timedelta(seconds=3))
        return (right - left, rows[left][2] if right - left == 1 else None)

    groups = []
    for read, key_id, ip, obj in reads:
        scope = (key_id, ip, obj)
        count, copy = nearby(copy_index.get(scope, ([], [])), utc(read.timestamp))
        if count != 1:
            continue
        if nearby(read_index[scope], utc(copy.timestamp))[0] != 1:
            continue
        members = sorted([read, copy], key=lambda event: (utc(event.timestamp), event.event_id))
        actions = Counter(event.api_action for event in members)
        groups.append({'kind': 'copy_source_read', 'confidence': 'medium', 'record_count': 2,
                       'successful_count': 2, 'failed_count': 0,
                       'first_seen': utc(members[0].timestamp), 'last_seen': utc(members[-1].timestamp),
                       'actions': [{'action': action, 'count': count} for action, count in sorted(actions.items())],
                       'event_ids': [event.event_id for event in members]})
    groups.sort(key=lambda group: (group['first_seen'], group['event_ids'][0]))
    return {'raw_record_count': len(records), 'group_count': len(groups),
            'grouped_record_count': len(groups) * 2, 'ungrouped_record_count': len(records) - len(groups) * 2,
            'groups': groups}
