# NOTE: These tests are written but not yet runnable.
# They will pass once Ritwik and Vedant complete:
#   - collectors/azure.py     (Day 2, Task 2.6) — implements _map_event()
#   - normalizer/schema.py    (Task 1.6)         — adds principal_id + location fields to ForensicEvent
#
# TODO(Yash): run pytest tests/test_azure_activitylog_mapping.py and verify all pass once above are done

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from collectors.azure import AzureActivityLogCollector


def _make_collector() -> AzureActivityLogCollector:
    # bypass __init__ (raises NotImplementedError until Ritwik implements it)
    return object.__new__(AzureActivityLogCollector)


def _make_event(
    operation_name: str = "Microsoft.Storage/storageAccounts/read",
    resource_provider: str = "Microsoft.Storage",
    client_ip: str | None = "1.2.3.4",
    resource_id: str = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
    resource_type: str | None = "Microsoft.Storage/storageAccounts",
    resource_group: str = "rg1",
    caller: str = "app-client-id-abc",
    status: str = "Succeeded",
    sub_status: str | None = None,
    correlation_id: str = "corr-abc-123",
    level: str = "Information",
    timestamp: datetime | None = None,
) -> SimpleNamespace:
    http_request = SimpleNamespace(client_ip_address=client_ip) if client_ip is not None else None
    return SimpleNamespace(
        event_timestamp=timestamp or datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc),
        operation_name=SimpleNamespace(value=operation_name),
        resource_provider_name=SimpleNamespace(value=resource_provider),
        http_request=http_request,
        resource_id=resource_id,
        resource_type=SimpleNamespace(value=resource_type) if resource_type is not None else None,
        resource_group=resource_group,
        caller=caller,
        status=SimpleNamespace(value=status),
        sub_status=SimpleNamespace(value=sub_status) if sub_status is not None else None,
        correlation_id=correlation_id,
        level=level,
    )


# ---------------------------------------------------------------------------
# Platform and timestamp
# ---------------------------------------------------------------------------

def test_platform_is_azure():
    event = _make_collector()._map_event(_make_event())
    assert event.platform == "azure"


def test_timestamp_preserved():
    ts = datetime(2026, 1, 15, 8, 30, tzinfo=timezone.utc)
    event = _make_collector()._map_event(_make_event(timestamp=ts))
    assert event.timestamp == ts


# ---------------------------------------------------------------------------
# Core field mappings
# ---------------------------------------------------------------------------

def test_api_action_from_operation_name():
    event = _make_collector()._map_event(_make_event())
    assert event.api_action == "Microsoft.Storage/storageAccounts/read"


def test_event_source_from_resource_provider():
    event = _make_collector()._map_event(_make_event())
    assert event.event_source == "Microsoft.Storage"


def test_source_ip_from_http_request():
    event = _make_collector()._map_event(_make_event(client_ip="5.6.7.8"))
    assert event.source_ip == "5.6.7.8"


def test_source_ip_none_when_no_http_request():
    event = _make_collector()._map_event(_make_event(client_ip=None))
    assert event.source_ip is None


def test_affected_resource_from_resource_id():
    event = _make_collector()._map_event(_make_event())
    assert "Microsoft.Storage/storageAccounts/sa1" in event.affected_resource


def test_resource_type_from_resource_type_value():
    event = _make_collector()._map_event(_make_event())
    assert event.resource_type == "Microsoft.Storage/storageAccounts"


def test_resource_type_none_when_missing():
    event = _make_collector()._map_event(_make_event(resource_type=None))
    assert event.resource_type is None


def test_location_from_resource_group():
    event = _make_collector()._map_event(_make_event(resource_group="my-rg"))
    assert event.location == "my-rg"


def test_principal_id_from_caller():
    event = _make_collector()._map_event(_make_event(caller="app-client-id-abc"))
    assert event.principal_id == "app-client-id-abc"


def test_collect_matches_app_claim_and_caller_without_attributing_other_apps():
    app_id = '11111111-2222-3333-4444-555555555555'
    object_event = _make_event(caller='service-principal-object-id')
    object_event.claims = {'appid': app_id.upper(), 'secret': 'do-not-store'}
    direct_event = _make_event(caller=app_id)
    other_event = _make_event(caller='another-object-id')
    other_event.claims = {'appid': 'another-app', 'aud': app_id}
    unidentifiable = _make_event(caller='service-principal-object-id')
    filters = []
    collector = _make_collector()
    collector._client = SimpleNamespace(activity_logs=SimpleNamespace(
        list=lambda **kwargs: (filters.append(kwargs['filter']) or iter([object_event, direct_event, other_event, unidentifiable]))
    ))
    result = collector.collect(app_id, datetime(2026, 5, 9, tzinfo=timezone.utc), datetime(2026, 5, 10, tzinfo=timezone.utc))
    assert len(result) == 2
    assert result[0].principal_id == 'service-principal-object-id'
    assert 'do-not-store' not in str(result[0].raw_data)
    assert 'caller eq' not in filters[0]


# ---------------------------------------------------------------------------
# Success / error_code from status and sub_status
# ---------------------------------------------------------------------------

def test_success_true_when_status_succeeded():
    event = _make_collector()._map_event(_make_event(status="Succeeded"))
    assert event.success is True


def test_success_false_when_status_not_succeeded():
    event = _make_collector()._map_event(_make_event(status="Failed"))
    assert event.success is False


def test_error_code_from_sub_status():
    event = _make_collector()._map_event(_make_event(sub_status="BadRequest"))
    assert event.error_code == "BadRequest"


def test_error_code_none_when_no_sub_status():
    event = _make_collector()._map_event(_make_event(sub_status=None))
    assert event.error_code is None


# ---------------------------------------------------------------------------
# raw_data contains correlation_id and level
# ---------------------------------------------------------------------------

def test_raw_data_contains_correlation_id():
    event = _make_collector()._map_event(_make_event(correlation_id="corr-abc-123"))
    assert event.raw_data["correlation_id"] == "corr-abc-123"


def test_raw_data_contains_level():
    event = _make_collector()._map_event(_make_event(level="Warning"))
    assert event.raw_data["level"] == "Warning"
