"""Bounded parsing of user-supplied CloudTrail audit files."""
import gzip
import hashlib
import io
import json
import zlib
from collections import Counter

from collectors.aws import _map_trail_record

MAX_UPLOAD = 16 * 1024 * 1024
MAX_DECODED = 64 * 1024 * 1024
MAX_RECORDS = 100000


def parse_evidence(content: bytes, access_key_id: str):
    if not content or len(content) > MAX_UPLOAD:
        raise ValueError('File is empty or exceeds the 16 MiB upload limit.')
    try:
        if content.startswith(b'\x1f\x8b'):
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
                decoded = stream.read(MAX_DECODED + 1)
        else:
            decoded = content
        if len(decoded) > MAX_DECODED:
            raise ValueError('Evidence exceeds the decompressed size limit.')
        obj = json.loads(decoded)
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError, zlib.error):
        raise ValueError('Invalid CloudTrail JSON or gzip file.') from None
    if not isinstance(obj, dict):
        raise ValueError('Expected a CloudTrail JSON object containing a Records or Events array.')
    has_records = isinstance(obj.get('Records'), list)
    has_events = isinstance(obj.get('Events'), list)
    if has_records == has_events:
        raise ValueError('Expected a CloudTrail JSON object containing exactly one Records or Events array.')
    records = obj['Records'] if has_records else obj['Events']
    file_format = 'CloudTrail Records JSON' if has_records else 'CloudTrail LookupEvents JSON'
    if len(records) > MAX_RECORDS:
        raise ValueError('Evidence exceeds the record limit.')
    digest = hashlib.sha256(content).hexdigest()
    events, seen = [], set()
    missing_key = other_key = duplicates = 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError('Evidence contains an invalid record.')
        if has_events:
            embedded = record.get('CloudTrailEvent')
            if isinstance(embedded, str):
                try:
                    embedded = json.loads(embedded)
                except (TypeError, ValueError):
                    raise ValueError('A LookupEvents record contains invalid CloudTrailEvent JSON.') from None
            if not isinstance(embedded, dict):
                raise ValueError('A LookupEvents record is missing its CloudTrailEvent object.')
            outer_id, inner_id = record.get('EventId'), embedded.get('eventID')
            if outer_id and inner_id and outer_id != inner_id:
                raise ValueError('A LookupEvents record has conflicting event IDs.')
            if record.get('EventName') and embedded.get('eventName') and record['EventName'] != embedded['eventName']:
                raise ValueError('A LookupEvents record has conflicting event names.')
            record = dict(embedded)
            if not inner_id and outer_id:
                record['eventID'] = outer_id
        identity = record.get('userIdentity') or {}
        if not isinstance(identity, dict):
            raise ValueError('Evidence contains an invalid identity.')
        key = identity.get('accessKeyId')
        if not key:
            missing_key += 1
            continue
        if key != access_key_id:
            other_key += 1
            continue
        event_id = record.get('eventID')
        if not isinstance(event_id, str) or not event_id:
            raise ValueError('A matching CloudTrail record is missing its event ID.')
        if event_id in seen:
            duplicates += 1
            continue
        try:
            event = _map_trail_record(record, '', '', digest)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError('A matching CloudTrail record has invalid event fields.') from None
        event.raw_data['evidence_source'] = {'method': 'cloudtrail-import', 'sha256': digest,
                                             'verification': 'user-supplied, not independently verified'}
        seen.add(event_id)
        events.append(event)
    actions = Counter(event.api_action for event in events)
    timestamps = [event.timestamp for event in events]
    return events, {'format': file_format, 'sha256': digest,
                    'total_records': len(records), 'matched_records': len(events),
                    'missing_key_records': missing_key, 'other_key_records': other_key,
                    'duplicate_records': duplicates, 'success_count': sum(event.success for event in events),
                    'failed_count': sum(not event.success for event in events),
                    'distinct_operations': len(actions),
                    'first_event': min(timestamps).isoformat() if timestamps else None,
                    'last_event': max(timestamps).isoformat() if timestamps else None,
                    'more_pages_indicated': bool(has_events and obj.get('NextToken')),
                    'verification': 'User-supplied evidence; AWS origin has not been independently verified.'}
