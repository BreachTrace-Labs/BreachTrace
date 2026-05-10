# STUB — Ritwik implements this (Day 2, Task 2.5)
#
# Required packages (add to requirements.txt):
#   google-cloud-logging>=3.5.0
#   google-auth>=2.20.0
#
# Dependencies before implementing:
#   - config.py must have GCP_PROJECT_ID + GCP_SERVICE_ACCOUNT_JSON (Ritwik, Task 1.1)
#   - normalizer/schema.py must have principal_id field added (Vedant, Task 1.6)
#
# How _map_entry works (GCP Cloud Audit Log → ForensicEvent):
#
#   entry.payload          dict  → protoPayload fields from Cloud Audit Log
#   entry.timestamp        datetime
#   entry.resource.type    str   → GCP resource type e.g. "gcs_bucket"
#
#   payload fields used:
#     "methodName"                             → api_action
#     "serviceName"                            → event_source
#     "requestMetadata.callerIp"               → source_ip
#     "requestMetadata.callerSuppliedUserAgent" → user_agent
#     "resourceName"                           → affected_resource
#     "authenticationInfo.principalEmail"      → principal_id  (needs Vedant schema update)
#     "status.code"                            → 0 = success, else error
#
# CloudTrail equivalent lookup:
#   filter: protoPayload.authenticationInfo.principalEmail = "<leaked_email>"
#           AND timestamp >= start AND timestamp <= end
#           AND logName:"cloudaudit.googleapis.com"

import logging
from datetime import datetime

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
        # Ritwik implements:
        #   from google.cloud import logging as gcp_logging
        #   from google.oauth2 import service_account
        #   import json, config
        #
        #   creds_json = json.loads(config.GCP_SERVICE_ACCOUNT_JSON)
        #   credentials = service_account.Credentials.from_service_account_info(
        #       creds_json, scopes=["https://www.googleapis.com/auth/logging.read"]
        #   )
        #   self._client = gcp_logging.Client(
        #       project=config.GCP_PROJECT_ID, credentials=credentials
        #   )
        raise NotImplementedError

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
        # Ritwik implements:
        #   filter_str = (
        #       f'protoPayload.authenticationInfo.principalEmail="{credential}" '
        #       f'AND timestamp>="{start_time.isoformat()}" '
        #       f'AND timestamp<="{end_time.isoformat()}" '
        #       'AND logName:"cloudaudit.googleapis.com"'
        #   )
        #   entries = self._client.list_entries(filter_=filter_str)
        #   return [self._map_entry(e) for e in entries]
        raise NotImplementedError

    def _map_entry(self, entry) -> ForensicEvent:
        """Map one GCP Cloud Audit Log entry to the shared ForensicEvent schema."""
        # Ritwik implements:
        #   payload = entry.payload if isinstance(entry.payload, dict) else {}
        #   status_code = payload.get("status", {}).get("code", 0)
        #   return ForensicEvent(
        #       platform="gcp",
        #       timestamp=entry.timestamp,
        #       api_action=payload.get("methodName", "Unknown"),
        #       event_source=payload.get("serviceName"),
        #       source_ip=payload.get("requestMetadata", {}).get("callerIp"),
        #       user_agent=payload.get("requestMetadata", {}).get("callerSuppliedUserAgent"),
        #       affected_resource=payload.get("resourceName"),
        #       resource_type=entry.resource.type if entry.resource else None,
        #       principal_id=payload.get("authenticationInfo", {}).get("principalEmail"),
        #       success=status_code == 0,
        #       error_code=str(status_code) if status_code else None,
        #       raw_data=payload,
        #   )
        raise NotImplementedError
