"""
Azure Activity Log collector.

Queries Azure Monitor Activity Logs for actions by a specific service principal
during an exposure window.

Required packages:
    azure-identity>=1.13.0
    azure-mgmt-monitor>=6.0.0
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)


class AzureActivityLogCollector(BaseCollector):
    """
    Queries Azure Monitor Activity Logs for actions by a specific service principal
    during the exposure window.
    """

    platform = "azure"

    def __init__(self) -> None:
        import config
        from azure.identity import ClientSecretCredential
        from azure.mgmt.monitor import MonitorManagementClient

        credential = ClientSecretCredential(
            tenant_id=config.AZURE_TENANT_ID,
            client_id=config.AZURE_CLIENT_ID,
            client_secret=config.AZURE_CLIENT_SECRET,
        )
        self._client = MonitorManagementClient(credential, config.AZURE_SUBSCRIPTION_ID)

    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        credential = Azure client_id / caller (the leaked app registration client ID).
        Queries Activity Logs for all actions during [start_time, end_time].
        """
        start_iso = _to_utc_iso(start_time)
        end_iso = _to_utc_iso(end_time)

        filter_str = (
            f"eventTimestamp ge '{start_iso}' "
            f"and eventTimestamp le '{end_iso}' "
            f"and caller eq '{credential}'"
        )

        logger.info("[Azure] Querying activity logs (%s → %s)", start_iso, end_iso)
        raw_events = self._client.activity_logs.list(filter=filter_str)
        events = [self._map_event(e) for e in raw_events]
        logger.info("[Azure] Collected %d forensic events", len(events))
        return events

    def _map_event(self, e: Any) -> ForensicEvent:
        """Map one Azure Activity Log event to the shared ForensicEvent schema."""
        # Safely read optional nested attributes
        operation_name = getattr(e, "operation_name", None)
        resource_provider = getattr(e, "resource_provider_name", None)
        http_request = getattr(e, "http_request", None)
        resource_type = getattr(e, "resource_type", None)
        status = getattr(e, "status", None)
        sub_status = getattr(e, "sub_status", None)
        level = getattr(e, "level", None)

        raw: dict[str, Any] = {
            "correlation_id": getattr(e, "correlation_id", None),
            "level": str(level) if level else None,
            "event_data_id": getattr(e, "event_data_id", None),
            "subscription_id": getattr(e, "subscription_id", None),
        }

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            platform="azure",
            timestamp=e.event_timestamp,
            api_action=operation_name.value if operation_name else "Unknown",
            event_source=resource_provider.value if resource_provider else None,
            source_ip=http_request.client_ip_address if http_request else None,
            user_agent=None,
            affected_resource=getattr(e, "resource_id", None),
            resource_type=resource_type.value if resource_type else None,
            location=getattr(e, "resource_group", None),
            principal_id=getattr(e, "caller", None),
            success=(status.value == "Succeeded") if status else True,
            error_code=sub_status.value if sub_status else None,
            raw_data=raw,
        )


def _to_utc_iso(dt: datetime) -> str:
    """Return an ISO-8601 string in UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

