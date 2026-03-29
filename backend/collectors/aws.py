import json
from datetime import datetime

import boto3

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent


def _json_safe_raw_event(raw_event: dict) -> dict:
    """Prepare the raw CloudTrail event for JSON/JSONB storage."""
    serializable_event = dict(raw_event)
    event_time = serializable_event.get("EventTime")
    if isinstance(event_time, datetime):
        serializable_event["EventTime"] = event_time.isoformat()
    return serializable_event


def _map_cloudtrail_event(raw_event: dict) -> ForensicEvent:
    """Convert one boto3 CloudTrail lookup event into the shared ForensicEvent schema."""
    nested_event = {}
    cloudtrail_event = raw_event.get("CloudTrailEvent")
    if isinstance(cloudtrail_event, str):
        try:
            parsed = json.loads(cloudtrail_event)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            nested_event = parsed

    resources = raw_event.get("Resources") or []
    first_resource = resources[0] if resources else {}
    error_code = raw_event.get("ErrorCode") or nested_event.get("errorCode")

    return ForensicEvent(
        platform="aws",
        timestamp=raw_event["EventTime"],
        api_action=raw_event["EventName"],
        event_source=raw_event.get("EventSource") or nested_event.get("eventSource"),
        source_ip=raw_event.get("SourceIPAddress") or nested_event.get("sourceIPAddress"),
        user_agent=raw_event.get("UserAgent") or nested_event.get("userAgent"),
        affected_resource=first_resource.get("ResourceName"),
        resource_type=first_resource.get("ResourceType"),
        success=error_code is None,
        error_code=error_code,
        raw_data=_json_safe_raw_event(raw_event),
    )


class AWSCloudTrailCollector(BaseCollector):
    """
    Collects AWS CloudTrail events for a given access key ID during an exposure window.
    TODO (Ritwik/Day 3): implement full pagination and event mapping.
    """

    platform = "aws"

    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        raise NotImplementedError("CloudTrail collector — implement on Day 3")
