"""
GCP Cloud Audit Log collector.

Queries Google Cloud Audit Logs for activity by a specific service account
email during an exposure window.

Required packages:
    google-cloud-logging>=3.5.0
    google-auth>=2.20.0
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)


class GCPAuditLogCollector(BaseCollector):
    """
    Queries Google Cloud Audit Logs for activity by a specific service account
    during the exposure window.
    """

    platform = "gcp"

    def __init__(self) -> None:
        import config
        from google.cloud import logging as gcp_logging
        from google.oauth2 import service_account

        creds_info: dict[str, Any] = json.loads(config.GCP_SERVICE_ACCOUNT_JSON)
        credentials = service_account.Credentials.from_service_account_info(
            creds_info,
            scopes=["https://www.googleapis.com/auth/logging.read"],
        )
        self._client = gcp_logging.Client(
            project=config.GCP_PROJECT_ID,
            credentials=credentials,
        )

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
        # Ensure UTC-aware ISO strings for the filter
        start_iso = _to_utc_iso(start_time)
        end_iso = _to_utc_iso(end_time)

        filter_str = (
            f'protoPayload.authenticationInfo.principalEmail="{credential}" '
            f'AND timestamp>="{start_iso}" '
            f'AND timestamp<="{end_iso}" '
            'AND logName:"cloudaudit.googleapis.com"'
        )

        logger.info("[GCP] Querying audit logs for %s (%s → %s)", credential, start_iso, end_iso)
        entries = self._client.list_entries(filter_=filter_str)
        events = [self._map_entry(e) for e in entries]
        logger.info("[GCP] Collected %d forensic events for %s", len(events), credential)
        return events

    def _map_entry(self, entry) -> ForensicEvent:
        """Map one GCP Cloud Audit Log entry to the shared ForensicEvent schema."""
        payload: dict[str, Any] = entry.payload if isinstance(entry.payload, dict) else {}

        status_block = payload.get("status", {}) or {}
        status_code: int = status_block.get("code", 0)

        request_meta: dict = payload.get("requestMetadata", {}) or {}
        auth_info: dict = payload.get("authenticationInfo", {}) or {}
        resource = getattr(entry, "resource", None)

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
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
            raw_data=payload,
        )


def _to_utc_iso(dt: datetime) -> str:
    """Return an ISO-8601 string in UTC (with trailing Z)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

