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
_MAX_ACTIVITY_EVENTS = 100_000
_APP_ID_CLAIMS = ('appid', 'azp', 'http://schemas.microsoft.com/identity/claims/appid')


def _matches_principal(event: Any, principal: str) -> bool:
    """Match the application ID or an exact caller ID; never infer from a secret."""
    expected = principal.strip().lower()
    if not expected:
        return False
    caller = getattr(event, 'caller', None)
    if isinstance(caller, str) and caller.strip().lower() == expected:
        return True
    claims = getattr(event, 'claims', None)
    if not isinstance(claims, dict):
        return False
    return any(isinstance(claims.get(key), str) and claims[key].strip().lower() == expected
               for key in _APP_ID_CLAIMS)


class AzureActivityLogCollector(BaseCollector):
    """
    Queries Azure Monitor Activity Logs for actions by a specific service principal
    during the exposure window.
    """

    platform = "azure"

    def __init__(self, reader: dict | None = None) -> None:
        import config
        from azure.identity import ClientSecretCredential
        from azure.mgmt.monitor import MonitorManagementClient

        reader = reader if reader is not None else {
            'tenant_id': config.AZURE_TENANT_ID, 'client_id': config.AZURE_CLIENT_ID,
            'client_secret': config.AZURE_CLIENT_SECRET, 'subscription_id': config.AZURE_SUBSCRIPTION_ID,
        }
        credential = ClientSecretCredential(
            tenant_id=reader['tenant_id'], client_id=reader['client_id'], client_secret=reader['client_secret'],
        )
        self._client = MonitorManagementClient(credential, reader['subscription_id'])

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

        # Azure's Activity Log API only documents time/resource filters.
        # Service-principal caller is commonly its object ID, while the app ID
        # appears in claims. Apply exact identity matching locally instead.
        filter_str = f"eventTimestamp ge '{start_iso}' and eventTimestamp le '{end_iso}'"

        logger.info("[Azure] Querying activity logs (%s → %s)", start_iso, end_iso)
        raw_events = self._client.activity_logs.list(filter=filter_str)
        events = []
        for index, event in enumerate(raw_events):
            if index >= _MAX_ACTIVITY_EVENTS:
                raise ValueError('Azure Activity Log collection limit exceeded; narrow the time window')
            if _matches_principal(event, credential):
                events.append(self._map_event(event))
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

