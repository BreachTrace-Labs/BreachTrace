"""
AWS CloudTrail forensic collector.
Queries lookup_events by AccessKeyId for the exposure window.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import boto3
from tenacity import retry, wait_exponential, stop_after_attempt

from collectors.base import BaseCollector
from config import get_settings
from normalizer.schema import ForensicEvent

settings = get_settings()


class AWSCollector(BaseCollector):

    def __init__(self):
        self.client = boto3.client(
            "cloudtrail",
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
    )
    def collect(
        self,
        access_key_id: str,
        exposure_start: datetime,
        exposure_end: datetime,
    ) -> list[ForensicEvent]:
        events: list[ForensicEvent] = []

        # Widen window to account for CloudTrail delivery lag
        start = exposure_start - timedelta(minutes=5)
        end = exposure_end + timedelta(minutes=20)

        params = {
            "LookupAttributes": [
                {"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}
            ],
            "StartTime": start,
            "EndTime": end,
            "MaxResults": 50,
        }

        while True:
            response = self.client.lookup_events(**params)

            for raw_event in response.get("Events", []):
                event = map_cloudtrail_event(raw_event)
                events.append(event)

            next_token = response.get("NextToken")
            if next_token:
                params["NextToken"] = next_token
            else:
                break

        return events


def map_cloudtrail_event(raw_event: dict) -> ForensicEvent:
    """Convert a raw CloudTrail event dict into a ForensicEvent."""
    import json

    # CloudTrail wraps the detailed event as a JSON string in 'CloudTrailEvent'
    detail = {}
    if "CloudTrailEvent" in raw_event:
        detail = json.loads(raw_event["CloudTrailEvent"])

    resources = raw_event.get("Resources", [])
    first_resource = resources[0] if resources else {}

    error_code = detail.get("errorCode")

    return ForensicEvent(
        event_id=str(uuid4()),
        platform="aws",
        timestamp=raw_event.get("EventTime", datetime.utcnow()),
        api_action=raw_event.get("EventName", ""),
        event_source=detail.get("eventSource", ""),
        source_ip=detail.get("sourceIPAddress"),
        user_agent=detail.get("userAgent"),
        affected_resource=first_resource.get("ResourceName"),
        resource_type=first_resource.get("ResourceType"),
        success=error_code is None,
        error_code=error_code,
        raw_data=detail,
    )
