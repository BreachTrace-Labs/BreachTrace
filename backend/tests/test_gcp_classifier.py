# NOTE: These tests are written but not yet runnable.
# They will pass once Shashank completes:
#   - classifier/taxonomy_gcp.py  (Day 1-2, Task 1.4) — 80+ GCP API mappings
#   - classifier/rules.py         (Day 3, Task 3.1)   — GCP platform dispatch + heuristics
#
# TODO(Yash): run pytest tests/test_gcp_classifier.py and verify all pass once above are done

from datetime import datetime, timezone

import pytest

from classifier.rules import classify_event, classify_events
from normalizer.schema import ForensicEvent


def _make_gcp_event(api_action: str, *, source_ip: str | None = "1.2.3.4") -> ForensicEvent:
    return ForensicEvent(
        platform="gcp",
        timestamp=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc),
        api_action=api_action,
        source_ip=source_ip,
        success=True,
    )


# ---------------------------------------------------------------------------
# Taxonomy lookups — these require Shashank to add entries to GCP_API_TAXONOMY
# ---------------------------------------------------------------------------

def test_storage_objects_get_is_data_access():
    event = classify_event(_make_gcp_event("storage.objects.get"))
    assert event.impact_category == "data_access"
    assert event.severity_weight == 2


def test_iam_sa_key_create_is_privilege_escalation():
    # Heuristic alone gives resource_abuse for "create" — taxonomy entry required
    event = classify_event(_make_gcp_event("iam.serviceAccountKeys.create"))
    assert event.impact_category == "privilege_escalation"
    assert event.severity_weight == 4


def test_compute_instances_insert_is_resource_abuse():
    # "insert" has no heuristic rule — taxonomy entry required
    event = classify_event(_make_gcp_event("compute.instances.insert"))
    assert event.impact_category == "resource_abuse"
    assert event.severity_weight == 3


# ---------------------------------------------------------------------------
# Heuristic fallbacks — work even with an empty GCP_API_TAXONOMY
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("api_action", "expected_category", "expected_severity"),
    [
        ("someservice.resource.list",         "reconnaissance",      1),
        ("someservice.resource.get",          "data_access",         2),
        ("someservice.resource.create",       "resource_abuse",      3),
        ("someservice.resource.delete",       "resource_abuse",      3),
        ("someservice.resource.update",       "resource_abuse",      3),
        ("someservice.resource.setIamPolicy", "privilege_escalation", 4),
        ("someservice.resource.signJwt",      "privilege_escalation", 4),
        ("someservice.resource.unknownverb",  "reconnaissance",      1),  # fallback
    ],
)
def test_gcp_heuristic_fallback(api_action, expected_category, expected_severity):
    event = classify_event(_make_gcp_event(api_action))
    assert event.impact_category == expected_category
    assert event.severity_weight == expected_severity


# ---------------------------------------------------------------------------
# Bulk escalation — same action + same IP >= 5 times → exfiltration
# ---------------------------------------------------------------------------

def test_bulk_gcp_data_access_escalates_to_exfiltration():
    # bigquery.tables.getData must classify as data_access initially (taxonomy required)
    events = [
        _make_gcp_event("bigquery.tables.getData", source_ip="9.9.9.9")
        for _ in range(5)
    ]
    classify_events(events)
    assert all(e.impact_category == "exfiltration" for e in events)
    assert all(e.severity_weight == 4 for e in events)


def test_bulk_escalation_does_not_trigger_below_threshold():
    events = [
        _make_gcp_event("bigquery.tables.getData", source_ip="9.9.9.9")
        for _ in range(4)
    ]
    classify_events(events)
    assert all(e.impact_category == "data_access" for e in events)


def test_bulk_escalation_scoped_to_same_ip():
    events = [
        _make_gcp_event("bigquery.tables.getData", source_ip=f"9.9.9.{i}")
        for i in range(1, 6)
    ]
    classify_events(events)
    # Different IPs — no single IP hits threshold
    assert all(e.impact_category == "data_access" for e in events)


# ---------------------------------------------------------------------------
# Mixed events — classify_events handles all correctly
# ---------------------------------------------------------------------------

def test_mixed_gcp_events_classified_correctly():
    events = [
        _make_gcp_event("someservice.resource.list"),           # reconnaissance
        _make_gcp_event("storage.objects.get"),                 # data_access
        _make_gcp_event("iam.serviceAccountKeys.create"),       # privilege_escalation
    ]
    classify_events(events)

    assert events[0].impact_category == "reconnaissance"
    assert events[0].severity_weight == 1

    assert events[1].impact_category == "data_access"
    assert events[1].severity_weight == 2

    assert events[2].impact_category == "privilege_escalation"
    assert events[2].severity_weight == 4


def test_classify_event_mutates_and_returns_same_object():
    event = _make_gcp_event("someservice.resource.list")
    result = classify_event(event)
    assert result is event
    assert event.impact_category is not None
