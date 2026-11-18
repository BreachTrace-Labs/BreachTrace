"""Validate and normalize a bounded local gcloud JSON export without cloud calls."""
import hashlib
import json
from datetime import datetime
from types import SimpleNamespace

from google.api_core.datetime_helpers import DatetimeWithNanoseconds

from collectors.gcp import GCPAuditLogCollector, _precise_timestamp
from research.gcp_historical import MAX_RECORDS, build_result

MAX_FILE_BYTES = 5 * 1024 * 1024


class ImportErrorSafe(ValueError):
    """A deliberately generic error that cannot include uploaded evidence."""


def import_export(data: bytes, payload: dict) -> dict:
    if len(data) > MAX_FILE_BYTES:
        raise ImportErrorSafe('The JSON file exceeds the 5 MB import limit.')
    try:
        rows = json.loads(data.decode('utf-8-sig'))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ImportErrorSafe('The file must contain a valid UTF-8 JSON array.') from None
    if not isinstance(rows, list):
        raise ImportErrorSafe('The file must contain a JSON array of Cloud Audit Log entries.')
    if len(rows) > MAX_RECORDS:
        raise ImportErrorSafe('The file exceeds the 2,000-record import limit.')

    start = _precise_timestamp(datetime.fromisoformat(payload['start_utc']))
    end = _precise_timestamp(datetime.fromisoformat(payload['end_utc']))
    project_prefix = f"projects/{payload['gcp_project_id']}/logs/cloudaudit.googleapis.com"
    principal = payload['principal_email'].lower()
    collector = object.__new__(GCPAuditLogCollector)
    seen = {}
    events = []
    duplicate_count = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get('protoPayload'), dict):
            raise ImportErrorSafe(f'Record {index + 1} is not a Cloud Audit Log entry.')
        audit = row['protoPayload']
        auth = audit.get('authenticationInfo')
        log_name = row.get('logName')
        actor = auth.get('principalEmail') if isinstance(auth, dict) else None
        if not isinstance(log_name, str) or not (log_name.startswith(project_prefix + '%2F') or log_name.startswith(project_prefix + '/')):
            raise ImportErrorSafe(f'Record {index + 1} does not belong to the requested project and audit log.')
        if not isinstance(actor, str) or actor.lower() != principal:
            raise ImportErrorSafe(f'Record {index + 1} does not match the requested principal.')
        if audit.get('@type', 'type.googleapis.com/google.cloud.audit.AuditLog') != 'type.googleapis.com/google.cloud.audit.AuditLog':
            raise ImportErrorSafe(f'Record {index + 1} is not a Cloud Audit Log entry.')
        try:
            timestamp = DatetimeWithNanoseconds.from_rfc3339(row['timestamp'])
            precise = _precise_timestamp(timestamp)
            if not start <= precise <= end:
                raise ImportErrorSafe(f'Record {index + 1} is outside the requested UTC range.')
            resource = row.get('resource')
            resource = SimpleNamespace(type=resource.get('type')) if isinstance(resource, dict) else None
            received = DatetimeWithNanoseconds.from_rfc3339(row['receiveTimestamp']) if row.get('receiveTimestamp') else None
            item = SimpleNamespace(payload=audit, timestamp=timestamp, resource=resource,
                                   insert_id=row.get('insertId'), log_name=log_name, operation=row.get('operation'),
                                   trace=row.get('trace'), span_id=row.get('spanId'), received_timestamp=received)
            event = collector._map_entry(item)
        except ImportErrorSafe:
            raise
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            raise ImportErrorSafe(f'Record {index + 1} has invalid timestamp or audit fields.') from None
        if event.source_record_id:
            row_digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
            previous = seen.get(event.source_record_id)
            if previous is not None:
                if previous != row_digest:
                    raise ImportErrorSafe(f'Record {index + 1} conflicts with an earlier record having the same provider identity.')
                duplicate_count += 1
                continue
            seen[event.source_record_id] = row_digest
        events.append(event)
    return build_result(events, payload, source='imported_json', extra={
        'input_record_count': len(rows), 'duplicate_record_count': duplicate_count,
        'source_sha256': hashlib.sha256(data).hexdigest(),
    })
