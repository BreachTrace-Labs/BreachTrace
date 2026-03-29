import json
from datetime import datetime

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent


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
        timestamp=raw_event["EventTime"],
        api_action=raw_event["EventName"],
        event_source=raw_event.get("EventSource") or nested_event.get("eventSource"),
        source_ip=raw_event.get("SourceIPAddress") or nested_event.get("sourceIPAddress"),
        user_agent=raw_event.get("UserAgent") or nested_event.get("userAgent"),
        affected_resource=first_resource.get("ResourceName"),
        resource_type=first_resource.get("ResourceType"),
        success=error_code is None,
        error_code=error_code,
        raw_data=raw_event,
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
