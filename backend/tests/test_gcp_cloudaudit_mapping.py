# NOTE: These tests are written but not yet runnable.
# They will pass once Ritwik and Vedant complete:
#   - collectors/gcp.py       (Day 2, Task 2.5) — implements _map_entry()
#   - normalizer/schema.py    (Task 1.6)         — adds principal_id field to ForensicEvent
#
# TODO(Yash): run pytest tests/test_gcp_cloudaudit_mapping.py and verify all pass once above are done

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from collectors.gcp import GCPAuditLogCollector


def _make_collector() -> GCPAuditLogCollector:
    # bypass __init__ (raises NotImplementedError until Ritwik implements it)
    return object.__new__(GCPAuditLogCollector)


def _make_entry(
    payload: dict | None = None,
    timestamp: datetime | None = None,
    resource_type: str = "gcs_bucket",
) -> SimpleNamespace:
    return SimpleNamespace(
        payload=payload if payload is not None else {},
        timestamp=timestamp or datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc),
        resource=SimpleNamespace(type=resource_type),
    )


_FULL_PAYLOAD = {
    "methodName": "storage.objects.get",
    "serviceName": "storage.googleapis.com",
    "requestMetadata": {
        "callerIp": "1.2.3.4",
        "callerSuppliedUserAgent": "gsutil/5.0",
    },
    "resourceName": "projects/_/buckets/my-bucket/objects/secret.txt",
    "authenticationInfo": {
        "principalEmail": "svc@project.iam.gserviceaccount.com",
    },
    "status": {"code": 0},
}


# ---------------------------------------------------------------------------
# Platform and timestamp
# ---------------------------------------------------------------------------

def test_platform_is_gcp():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.platform == "gcp"


def test_timestamp_preserved():
    ts = datetime(2026, 1, 15, 8, 30, tzinfo=timezone.utc)
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD, timestamp=ts))
    assert event.timestamp == ts


# ---------------------------------------------------------------------------
# Core field mappings
# ---------------------------------------------------------------------------

def test_api_action_from_method_name():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.api_action == "storage.objects.get"


def test_event_source_from_service_name():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.event_source == "storage.googleapis.com"


def test_source_ip_from_caller_ip():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.source_ip == "1.2.3.4"


def test_user_agent_from_caller_supplied_user_agent():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.user_agent == "gsutil/5.0"


def test_affected_resource_from_resource_name():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.affected_resource == "projects/_/buckets/my-bucket/objects/secret.txt"


def test_resource_type_from_entry_resource_type():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD, resource_type="gcs_bucket"))
    assert event.resource_type == "gcs_bucket"


def test_principal_id_from_principal_email():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.principal_id == "svc@project.iam.gserviceaccount.com"


# ---------------------------------------------------------------------------
# Success / error_code from status.code
# ---------------------------------------------------------------------------

def test_success_true_when_status_code_zero():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.success is True


def test_success_false_when_status_code_nonzero():
    payload = {**_FULL_PAYLOAD, "status": {"code": 7}}
    event = _make_collector()._map_entry(_make_entry(payload))
    assert event.success is False


def test_error_code_none_on_success():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.error_code is None


def test_error_code_set_on_failure():
    payload = {**_FULL_PAYLOAD, "status": {"code": 7}}
    event = _make_collector()._map_entry(_make_entry(payload))
    assert event.error_code == "7"


# ---------------------------------------------------------------------------
# raw_data is the full payload dict
# ---------------------------------------------------------------------------

def test_raw_data_is_payload():
    event = _make_collector()._map_entry(_make_entry(_FULL_PAYLOAD))
    assert event.raw_data == _FULL_PAYLOAD


# ---------------------------------------------------------------------------
# Missing optional fields default gracefully
# ---------------------------------------------------------------------------

def test_missing_optional_fields_do_not_raise():
    event = _make_collector()._map_entry(_make_entry({}))
    assert event.platform == "gcp"
    assert event.api_action == "Unknown"
    assert event.event_source is None
    assert event.source_ip is None
    assert event.user_agent is None
    assert event.affected_resource is None
    assert event.principal_id is None
    assert event.success is True
    assert event.error_code is None
