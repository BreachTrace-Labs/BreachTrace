# STUB — Ritwik implements this (Day 2, Task 2.6)
#
# Required packages (add to requirements.txt):
#   azure-mgmt-monitor>=6.0.0
#   azure-identity>=1.13.0
#   azure-mgmt-resource>=23.0.0
#
# Dependencies before implementing:
#   - config.py must have AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
#     AZURE_SUBSCRIPTION_ID (Ritwik, Task 1.1)
#   - normalizer/schema.py must have principal_id + location fields (Vedant, Task 1.6)
#
# How _map_event works (Azure Activity Log event → ForensicEvent):
#
#   e.event_timestamp                      → timestamp
#   e.operation_name.value                 → api_action  e.g. "Microsoft.Storage/storageAccounts/read"
#   e.resource_provider_name.value         → event_source
#   e.http_request.client_ip_address       → source_ip  (e.http_request may be None)
#   e.resource_id                          → affected_resource
#   e.resource_type.value                  → resource_type  (may be None)
#   e.resource_group                       → location  (needs Vedant schema update)
#   e.caller                               → principal_id  (needs Vedant schema update)
#   e.status.value == "Succeeded"          → success
#   e.sub_status.value                     → error_code  (may be None)
#   e.correlation_id + e.level             → raw_data

import logging
from datetime import datetime

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
        # Ritwik implements:
        #   from azure.identity import ClientSecretCredential
        #   from azure.mgmt.monitor import MonitorManagementClient
        #   import config
        #
        #   credential = ClientSecretCredential(
        #       tenant_id=config.AZURE_TENANT_ID,
        #       client_id=config.AZURE_CLIENT_ID,
        #       client_secret=config.AZURE_CLIENT_SECRET,
        #   )
        #   self._client = MonitorManagementClient(credential, config.AZURE_SUBSCRIPTION_ID)
        raise NotImplementedError

    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        credential = Azure client_id (the leaked app registration ID).
        Queries Activity Logs for all actions during [start_time, end_time].
        """
        # Ritwik implements:
        #   filter_str = (
        #       f"eventTimestamp ge '{start_time.isoformat()}' "
        #       f"and eventTimestamp le '{end_time.isoformat()}' "
        #       f"and caller eq '{credential}'"
        #   )
        #   events = self._client.activity_logs.list(filter=filter_str)
        #   return [self._map_event(e) for e in events]
        raise NotImplementedError

    def _map_event(self, e) -> ForensicEvent:
        """Map one Azure Activity Log event to the shared ForensicEvent schema."""
        # Ritwik implements:
        #   return ForensicEvent(
        #       platform="azure",
        #       timestamp=e.event_timestamp,
        #       api_action=e.operation_name.value if e.operation_name else "Unknown",
        #       event_source=e.resource_provider_name.value if e.resource_provider_name else None,
        #       source_ip=e.http_request.client_ip_address if e.http_request else None,
        #       affected_resource=e.resource_id,
        #       resource_type=e.resource_type.value if e.resource_type else None,
        #       location=e.resource_group,
        #       principal_id=e.caller,
        #       success=e.status.value == "Succeeded" if e.status else True,
        #       error_code=e.sub_status.value if e.sub_status else None,
        #       raw_data={"correlation_id": e.correlation_id, "level": str(e.level)},
        #   )
        raise NotImplementedError
