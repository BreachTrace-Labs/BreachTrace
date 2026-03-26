# AWS classifier unit tests
# TODO (Yash/Day 4): add coverage for every taxonomy category.

import pytest
from normalizer.schema import ForensicEvent
from classifier.rules import classify_event
from datetime import datetime, timezone


def _make_event(api_action: str) -> ForensicEvent:
    return ForensicEvent(
        event_id="test-id",
        platform="aws",
        timestamp=datetime.now(timezone.utc),
        api_action=api_action,
        event_source="s3.amazonaws.com",
        success=True,
        raw_data={},
    )


def test_list_buckets_is_reconnaissance():
    event = classify_event(_make_event("ListBuckets"))
    assert event.impact_category == "reconnaissance"
    assert event.severity_weight == 1


def test_get_object_is_data_access():
    event = classify_event(_make_event("GetObject"))
    assert event.impact_category == "data_access"
    assert event.severity_weight == 2


def test_run_instances_is_resource_abuse():
    event = classify_event(_make_event("RunInstances"))
    assert event.impact_category == "resource_abuse"
    assert event.severity_weight == 3


def test_create_access_key_is_privilege_escalation():
    event = classify_event(_make_event("CreateAccessKey"))
    assert event.impact_category == "privilege_escalation"
    assert event.severity_weight == 4


def test_unknown_action_returns_none():
    event = classify_event(_make_event("SomeUnknownAction"))
    assert event.impact_category is None
    assert event.severity_weight is None
