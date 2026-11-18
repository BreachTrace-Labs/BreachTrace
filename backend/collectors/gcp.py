"""
GCP Cloud Audit Log collector.

Queries Google Cloud Audit Logs for activity by a specific service account
email during an exposure window.

Required packages:
    google-cloud-logging>=3.5.0
    google-auth>=2.20.0
"""
from __future__ import annotations

import logging
import json
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent
from redaction import redact

logger = logging.getLogger(__name__)
_DEFAULT_MAX_EVENTS = 100_000
_DEFAULT_PAGE_SIZE = 500
_DEFAULT_MAX_WINDOW_DAYS = 90


class GCPAuditLogCollector(BaseCollector):
    """
    Queries Google Cloud Audit Logs for activity by a specific service account
    during the exposure window.
    """

    platform = "gcp"

    def __init__(self, reader: dict | None = None, *, max_events: int = _DEFAULT_MAX_EVENTS,
                 page_size: int = _DEFAULT_PAGE_SIZE, max_window_days: int = _DEFAULT_MAX_WINDOW_DAYS) -> None:
        import config
        from google.cloud import logging as gcp_logging
        from gcp_reader import reader_credentials
        if max_events < 1 or not 1 <= page_size <= 1000 or max_window_days < 1:
            raise ValueError('Invalid GCP collection limits')
        self._max_events, self._page_size, self._max_window_days = max_events, page_size, max_window_days
        legacy = reader is None
        reader = reader if reader is not None else {'service_account_json': config.GCP_SERVICE_ACCOUNT_JSON}
        project_id, credentials = reader_credentials(reader)
        if legacy:
            project_id = config.GCP_PROJECT_ID or project_id
        self._reader_principal = (reader.get('reader_service_account') if reader.get('auth_mode') == 'impersonation'
                                  else json.loads(reader['service_account_json']).get('client_email'))
        self._source_principal = (json.loads(reader['source_service_account_json']).get('client_email')
                                  if reader.get('source_service_account_json') else None)
        self._client = gcp_logging.Client(project=project_id, credentials=credentials)

    def close(self) -> None:
        """Release the Cloud Logging transport after an investigation."""
        self._client.close()

    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        credential = GCP service account email (principalEmail of the leaked key).
        Queries Cloud Audit Logs for all activity during [start_time, end_time].
        """
        from detector.patterns import GCP_CLIENT_EMAIL_PATTERN
        if not isinstance(credential, str) or not GCP_CLIENT_EMAIL_PATTERN.fullmatch(credential.lower()):
            raise ValueError('A valid GCP service-account principal is required for this collection')
        if getattr(self, '_reader_principal', None) and self._reader_principal.lower() == credential.lower():
            raise ValueError('The GCP log reader must be separate from the investigated service account')
        if getattr(self, '_source_principal', None) and self._source_principal.lower() == credential.lower():
            raise ValueError('The GCP impersonation source must be separate from the investigated service account')
        start_utc = _as_utc(start_time)
        end_utc = _as_utc(end_time)
        if end_utc < start_utc:
            raise ValueError('GCP collection end must not precede its start')
        if end_utc - start_utc > timedelta(days=self._max_window_days):
            raise ValueError('GCP collection window exceeds the configured limit')
        # Ensure UTC-aware ISO strings for the filter
        start_iso = _to_utc_iso(start_time)
        end_iso = _to_utc_iso(end_time)

        filter_str = (
            f'protoPayload.authenticationInfo.principalEmail={json.dumps(credential)} '
            f'AND timestamp>="{start_iso}" '
            f'AND timestamp<="{end_iso}" '
            'AND logName:"cloudaudit.googleapis.com"'
        )

        logger.info("[GCP] Querying audit logs (%s → %s)", start_iso, end_iso)
        entries = self._client.list_entries(filter_=filter_str, order_by='timestamp asc', page_size=self._page_size)
        events = []
        seen = set()
        for index, entry in enumerate(entries):
            if index >= self._max_events:
                # Fail the attempt instead of presenting a partial timeline as complete.
                raise ValueError('GCP audit log collection limit exceeded; narrow the time window')
            event = self._map_entry(entry)
            if event.source_record_id and event.source_record_id in seen:
                continue
            if event.source_record_id:
                seen.add(event.source_record_id)
            events.append(event)
        logger.info("[GCP] Collected %d forensic events", len(events))
        return events

    def _map_entry(self, entry) -> ForensicEvent:
        """Map one GCP Cloud Audit Log entry to the shared ForensicEvent schema."""
        payload: dict[str, Any] = entry.payload if isinstance(entry.payload, dict) else {}

        status_code = _status_code(payload.get('status'))

        request_meta: dict = payload.get("requestMetadata", {}) or {}
        auth_info: dict = payload.get("authenticationInfo", {}) or {}
        resource = getattr(entry, "resource", None)

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            source_record_id=_source_record_id(entry),
            platform="gcp",
            timestamp=entry.timestamp,
            api_action=payload.get("methodName", "Unknown"),
            event_source=payload.get("serviceName"),
            source_ip=request_meta.get("callerIp"),
            user_agent=request_meta.get("callerSuppliedUserAgent"),
            affected_resource=payload.get("resourceName"),
            resource_type=resource.type if resource else None,
            principal_id=auth_info.get("principalEmail"),
            success=(status_code == 0),
            error_code=str(status_code) if status_code else None,
            raw_data=_safe_evidence(payload, entry),
        )


def _status_code(status: Any) -> int:
    # An empty protobuf status represents OK. Nonempty malformed statuses are
    # not evidence of success or failure, so fail collection rather than guess.
    if status is None or status == {}:
        return 0
    if not isinstance(status, dict) or isinstance(status.get('code'), bool):
        raise ValueError('GCP audit log contains an invalid status')
    code = status.get('code')
    if isinstance(code, str) and code.isdecimal():
        code = int(code)
    if not isinstance(code, int) or not 0 <= code <= 16:
        raise ValueError('GCP audit log contains an invalid status')
    return code


def _safe_evidence(payload: dict, entry: Any) -> dict:
    """Keep forensic fields, not arbitrary provider request/response bodies."""
    allowed = ('@type', 'serviceName', 'methodName', 'resourceName', 'authenticationInfo', 'status')
    safe = {key: redact(payload[key]) for key in allowed if key in payload}
    request_meta = payload.get('requestMetadata')
    if isinstance(request_meta, dict):
        safe['requestMetadata'] = redact({key: request_meta[key] for key in ('callerIp', 'callerSuppliedUserAgent') if key in request_meta})
    authz = payload.get('authorizationInfo')
    if isinstance(authz, list):
        safe['authorizationInfo'] = [redact({k: item[k] for k in ('resource', 'permission', 'granted') if k in item}) for item in authz if isinstance(item, dict)]
    metadata = {}
    for attr, key in (('insert_id', 'insert_id'), ('log_name', 'log_name'), ('trace', 'trace'), ('span_id', 'span_id')):
        value = getattr(entry, attr, None)
        if isinstance(value, str):
            metadata[key] = redact(value)
    received = getattr(entry, 'received_timestamp', None)
    if isinstance(received, datetime):
        metadata['receive_timestamp'] = received.isoformat()
    timestamp = getattr(entry, 'timestamp', None)
    if isinstance(timestamp, datetime):
        metadata['timestamp_precise'] = _precise_timestamp(timestamp)
    operation = getattr(entry, 'operation', None)
    if isinstance(operation, dict):
        metadata['operation'] = redact({key: operation[key] for key in ('id', 'producer', 'first', 'last') if key in operation})
    if metadata:
        safe['_gcp_log_entry'] = metadata
    return safe


def _precise_timestamp(value: datetime) -> str:
    nanos = getattr(value, 'nanosecond', value.microsecond * 1000)
    return _as_utc(value).strftime('%Y-%m-%dT%H:%M:%S') + f'.{nanos:09d}Z'


def _source_record_id(entry: Any) -> str | None:
    log_name = getattr(entry, 'log_name', None)
    insert_id = getattr(entry, 'insert_id', None)
    timestamp = getattr(entry, 'timestamp', None)
    if not isinstance(log_name, str) or not log_name or not isinstance(insert_id, str) or not insert_id or not isinstance(timestamp, datetime):
        return None
    identity = json.dumps(['gcp-log-entry-v1', log_name, insert_id, _precise_timestamp(timestamp)], ensure_ascii=True, separators=(',', ':'))
    return hashlib.sha256(identity.encode('utf-8')).hexdigest()


def _to_utc_iso(dt: datetime) -> str:
    """Return an RFC 3339 timestamp without losing fractional seconds."""
    return _as_utc(dt).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

