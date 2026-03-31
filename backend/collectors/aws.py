import json
import logging
from datetime import datetime, timedelta

import boto3
from tenacity import retry, stop_after_attempt, wait_exponential

import config
from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

# CloudTrail has up to 15-minute delivery delay — add a buffer when querying.
_CLOUDTRAIL_END_BUFFER_MINUTES = 20


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

    Uses the admin AWS credentials (from config) to query CloudTrail — the leaked
    key's ID is passed as a lookup attribute, not used for authentication.
    """

    platform = "aws"

    def __init__(self) -> None:
        self._client = boto3.client(
            "cloudtrail",
            region_name=config.AWS_REGION,
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
        )

    # ------------------------------------------------------------------
    # Retryable CloudTrail lookup (handles throttling / transient errors)
    # ------------------------------------------------------------------
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _lookup_page(
        self,
        access_key_id: str,
        start_time: datetime,
        end_time: datetime,
        next_token: str | None = None,
    ) -> dict:
        """Execute a single paginated CloudTrail LookupEvents call."""
        params: dict = {
            "LookupAttributes": [
                {
                    "AttributeKey": "AccessKeyId",
                    "AttributeValue": access_key_id,
                }
            ],
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": 50,
        }
        if next_token:
            params["NextToken"] = next_token

        return self._client.lookup_events(**params)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        Query CloudTrail for all API calls made with *credential* (an AKIA… key ID)
        between *start_time* and *end_time*.

        Adds a 20-minute buffer to *end_time* to account for CloudTrail's delivery delay.
        Paginates automatically until all events are retrieved.
        """
        adjusted_end = end_time + timedelta(minutes=_CLOUDTRAIL_END_BUFFER_MINUTES)
        logger.info(
            "CloudTrail lookup: key=%s window=%s → %s (buffered to %s)",
            credential,
            start_time.isoformat(),
            end_time.isoformat(),
            adjusted_end.isoformat(),
        )

        events: list[ForensicEvent] = []
        next_token: str | None = None

        while True:
            response = self._lookup_page(credential, start_time, adjusted_end, next_token)

            for raw_event in response.get("Events", []):
                try:
                    forensic_event = _map_cloudtrail_event(raw_event)
                    events.append(forensic_event)
                except Exception:
                    logger.exception("Failed to map CloudTrail event: %s", raw_event.get("EventId"))

            next_token = response.get("NextToken")
            if not next_token:
                break

        logger.info("CloudTrail returned %d events for key %s", len(events), credential)
        return events
