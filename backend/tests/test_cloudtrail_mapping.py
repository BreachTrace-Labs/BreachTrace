import json
from datetime import datetime, timezone

import pytest

from collectors.aws import _map_cloudtrail_event


def _event_time() -> datetime:
    return datetime(2026, 3, 29, 12, 0, tzinfo=timezone.utc)


def test_map_cloudtrail_event_maps_lookup_event_fields():
    raw_event = {
        "EventId": "evt-1",
        "EventTime": _event_time(),
        "EventName": "GetObject",
        "EventSource": "s3.amazonaws.com",
        "Resources": [
            {
                "ResourceType": "AWS::S3::Object",
                "ResourceName": "breachtrace-bucket/report.csv",
            }
        ],
        "CloudTrailEvent": json.dumps(
            {
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2.0",
            }
        ),
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.platform == "aws"
    assert event.timestamp == raw_event["EventTime"]
    assert event.api_action == "GetObject"
    assert event.event_source == "s3.amazonaws.com"
    assert event.source_ip == "1.2.3.4"
    assert event.user_agent == "aws-cli/2.0"
    assert event.affected_resource == "breachtrace-bucket/report.csv"
    assert event.resource_type == "AWS::S3::Object"
    assert event.success is True
    assert event.error_code is None
    assert event.raw_data == raw_event


def test_map_cloudtrail_event_uses_none_for_missing_optional_fields():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "ListBuckets",
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.event_source is None
    assert event.source_ip is None
    assert event.user_agent is None
    assert event.affected_resource is None
    assert event.resource_type is None
    assert event.success is True


def test_map_cloudtrail_event_marks_failed_events_from_nested_error_code():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "GetObject",
        "EventSource": "s3.amazonaws.com",
        "CloudTrailEvent": json.dumps(
            {
                "sourceIPAddress": "5.6.7.8",
                "userAgent": "Boto3/1.35",
                "errorCode": "AccessDenied",
            }
        ),
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.source_ip == "5.6.7.8"
    assert event.user_agent == "Boto3/1.35"
    assert event.error_code == "AccessDenied"
    assert event.success is False


def test_map_cloudtrail_event_prefers_top_level_ip_and_user_agent():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "GetObject",
        "SourceIPAddress": "10.0.0.1",
        "UserAgent": "aws-sdk-python",
        "CloudTrailEvent": json.dumps(
            {
                "sourceIPAddress": "5.6.7.8",
                "userAgent": "Boto3/1.35",
            }
        ),
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.source_ip == "10.0.0.1"
    assert event.user_agent == "aws-sdk-python"


def test_map_cloudtrail_event_marks_failed_events_from_top_level_error_code():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "RunInstances",
        "ErrorCode": "UnauthorizedOperation",
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.error_code == "UnauthorizedOperation"
    assert event.success is False


def test_map_cloudtrail_event_falls_back_to_nested_event_source():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "DescribeInstances",
        "CloudTrailEvent": json.dumps(
            {
                "eventSource": "ec2.amazonaws.com",
                "sourceIPAddress": "9.9.9.9",
            }
        ),
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.event_source == "ec2.amazonaws.com"
    assert event.source_ip == "9.9.9.9"


def test_map_cloudtrail_event_uses_only_first_resource():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "GetObject",
        "Resources": [
            {
                "ResourceType": "AWS::S3::Object",
                "ResourceName": "bucket/first.csv",
            },
            {
                "ResourceType": "AWS::S3::Object",
                "ResourceName": "bucket/second.csv",
            },
        ],
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.affected_resource == "bucket/first.csv"
    assert event.resource_type == "AWS::S3::Object"


def test_map_cloudtrail_event_ignores_invalid_nested_json():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "ListBuckets",
        "CloudTrailEvent": "{not-json",
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.success is True
    assert event.source_ip is None
    assert event.user_agent is None


def test_map_cloudtrail_event_handles_none_nested_payload():
    raw_event = {
        "EventTime": _event_time(),
        "EventName": "ListBuckets",
        "CloudTrailEvent": None,
        "Resources": None,
    }

    event = _map_cloudtrail_event(raw_event)

    assert event.source_ip is None
    assert event.user_agent is None
    assert event.affected_resource is None
    assert event.resource_type is None


def test_map_cloudtrail_event_requires_timestamp_and_action():
    with pytest.raises(KeyError):
        _map_cloudtrail_event({})
