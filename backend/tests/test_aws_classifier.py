from datetime import datetime, timezone

import pytest

from classifier.rules import classify_all_events, classify_event, classify_events
from db.models import IncidentRecord as ORMIncidentRecord
from db.models import ForensicEvent as ORMForensicEvent
from normalizer.schema import ForensicEvent


def _make_event(
    api_action: str,
    *,
    event_source: str | None = "s3.amazonaws.com",
    source_ip: str | None = "1.2.3.4",
) -> ForensicEvent:
    return ForensicEvent(
        event_id="test-event",
        platform="aws",
        timestamp=datetime(2026, 3, 30, 12, 0, tzinfo=timezone.utc),
        api_action=api_action,
        event_source=event_source,
        source_ip=source_ip,
        success=True,
        raw_data={"eventName": api_action, "eventSource": event_source},
    )


@pytest.mark.parametrize(
    ("api_action", "event_source", "expected_category", "expected_severity"),
    [
        ("ListBuckets", "s3.amazonaws.com", "reconnaissance", 1),
        ("GetObject", "s3.amazonaws.com", "data_access", 3),
        ("CreateAccessKey", "iam.amazonaws.com", "privilege_escalation", 4),
        ("RunInstances", "ec2.amazonaws.com", "resource_abuse", 3),
        ("GetSecretValue", "secretsmanager.amazonaws.com", "data_access", 4),
        ("DeleteTrail", "cloudtrail.amazonaws.com", "resource_abuse", 4),
        ("DescribeAlarms", "monitoring.amazonaws.com", "reconnaissance", 1),
        ("StartQueryExecution", "athena.amazonaws.com", "resource_abuse", 2),
    ],
)
def test_classify_event_uses_exact_taxonomy_mapping(
    api_action: str,
    event_source: str,
    expected_category: str,
    expected_severity: int,
):
    event = classify_event(_make_event(api_action, event_source=event_source))

    assert event.impact_category == expected_category
    assert event.severity_weight == expected_severity


def test_classify_event_accepts_service_prefixed_actions_directly():
    event = classify_event(
        _make_event("iam:CreateAccessKey", event_source=None)
    )

    assert event.impact_category == "privilege_escalation"
    assert event.severity_weight == 4


def test_classify_event_falls_back_to_unique_taxonomy_suffix_when_source_missing():
    event = classify_event(_make_event("GetCallerIdentity", event_source=None))

    assert event.impact_category == "reconnaissance"
    assert event.severity_weight == 1


@pytest.mark.parametrize(
    ("api_action", "expected_category", "expected_severity"),
    [
        ("ListWidgets", "reconnaissance", 1),
        ("DescribeWidgets", "reconnaissance", 1),
        ("GetWidget", "data_access", 2),
        ("PutWidget", "resource_abuse", 3),
        ("CreateWidget", "resource_abuse", 3),
        ("DeleteWidget", "resource_abuse", 3),
        ("UpdateWidget", "resource_abuse", 3),
        ("ModifyWidget", "resource_abuse", 3),
        ("RunWidget", "resource_abuse", 3),
        ("StartWidget", "resource_abuse", 3),
        ("StopWidget", "resource_abuse", 3),
        ("TerminateWidget", "resource_abuse", 3),
        ("SomeUnknownAction", "reconnaissance", 1),
    ],
)
def test_classify_event_uses_heuristics_for_unknown_actions(
    api_action: str,
    expected_category: str,
    expected_severity: int,
):
    event = classify_event(
        _make_event(api_action, event_source="custom.amazonaws.com")
    )

    assert event.impact_category == expected_category
    assert event.severity_weight == expected_severity


@pytest.mark.parametrize(
    ("api_action", "event_source"),
    [
        ("CreateAccessKey", "custom.amazonaws.com"),
        ("AttachUserPolicy", "custom.amazonaws.com"),
        ("PutRolePolicy", "custom.amazonaws.com"),
        ("AssumeRole", "custom.amazonaws.com"),
        ("UpdateAssumeRolePolicy", "custom.amazonaws.com"),
    ],
)
def test_special_overrides_take_priority_over_generic_heuristics(
    api_action: str,
    event_source: str,
):
    event = classify_event(_make_event(api_action, event_source=event_source))

    assert event.impact_category == "privilege_escalation"
    assert event.severity_weight == 4


def test_classify_event_mutates_and_returns_the_same_object():
    event = _make_event("ListBuckets")

    result = classify_event(event)

    assert result is event
    assert event.impact_category == "reconnaissance"
    assert event.severity_weight == 1


def test_exact_taxonomy_match_beats_generic_get_heuristic():
    event = classify_event(_make_event("GetObject", event_source="s3.amazonaws.com"))

    assert event.impact_category == "data_access"
    assert event.severity_weight == 3


def test_classify_events_returns_the_same_list_object():
    events = [_make_event("ListBuckets"), _make_event("GetObject")]

    result = classify_events(events)

    assert result is events


def test_bulk_data_access_from_same_ip_remains_access_with_raised_severity():
    events = [
        _make_event("GetObject", event_source="s3.amazonaws.com", source_ip="9.9.9.9")
        for _ in range(5)
    ]

    classify_events(events)

    assert all(event.impact_category == "data_access" for event in events)
    assert all(event.severity_weight == 4 for event in events)


def test_bulk_escalation_does_not_trigger_below_threshold():
    events = [
        _make_event("GetObject", event_source="s3.amazonaws.com", source_ip="9.9.9.9")
        for _ in range(4)
    ]

    classify_events(events)

    assert all(event.impact_category == "data_access" for event in events)
    assert all(event.severity_weight == 3 for event in events)


def test_bulk_escalation_is_scoped_to_same_ip():
    events = [
        _make_event("GetObject", event_source="s3.amazonaws.com", source_ip=f"9.9.9.{i}")
        for i in range(1, 6)
    ]

    classify_events(events)

    assert all(event.impact_category == "data_access" for event in events)
    assert all(event.severity_weight == 3 for event in events)


def test_bulk_escalation_is_scoped_to_same_action():
    events = [
        _make_event("GetObject", event_source="s3.amazonaws.com", source_ip="9.9.9.9")
        for _ in range(4)
    ]
    events.append(
        _make_event("GetObjectVersion", event_source="s3.amazonaws.com", source_ip="9.9.9.9")
    )

    classify_events(events)

    assert all(event.impact_category == "data_access" for event in events)
    assert all(event.severity_weight == 3 for event in events)


def test_bulk_escalation_does_not_apply_to_non_data_access_events():
    events = [
        _make_event("PutObject", event_source="s3.amazonaws.com", source_ip="9.9.9.9")
        for _ in range(5)
    ]

    classify_events(events)

    assert all(event.impact_category == "resource_abuse" for event in events)
    assert all(event.severity_weight == 3 for event in events)


def test_bulk_escalation_does_not_apply_when_source_ip_is_missing():
    events = [
        _make_event("GetObject", event_source="s3.amazonaws.com", source_ip=None)
        for _ in range(5)
    ]

    classify_events(events)

    assert all(event.impact_category == "data_access" for event in events)
    assert all(event.severity_weight == 3 for event in events)


class _FakeDB:
    def __init__(self, incident):
        self._incident = incident
        self.commits = 0

    def get(self, model, incident_id):
        if self._incident and incident_id == self._incident.incident_id:
            return self._incident
        return None

    def commit(self):
        self.commits += 1

    def refresh(self, obj):
        pass  # no-op for testing


def _make_orm_event(
    api_action: str,
    *,
    event_source: str = "s3.amazonaws.com",
    source_ip: str | None = "1.2.3.4",
) -> ORMForensicEvent:
    return ORMForensicEvent(
        event_id=f"{api_action}-{source_ip or 'none'}",
        incident_id="incident-1",
        platform="aws",
        timestamp=datetime(2026, 3, 30, 12, 0, tzinfo=timezone.utc),
        api_action=api_action,
        event_source=event_source,
        source_ip=source_ip,
        success=True,
        raw_data={"eventName": api_action, "eventSource": event_source},
    )


def _make_incident_with_events(events: list[ORMForensicEvent]) -> ORMIncidentRecord:
    incident = ORMIncidentRecord(
        incident_id="incident-1",
        credential_type="aws_access_key",
        credential_hint="AKIA****MPLE",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        repo_url="https://example.com/repo",
        commit_hash="abc123",
        exposure_start=datetime(2026, 3, 30, 12, 0, tzinfo=timezone.utc),
        status="classifying",
    )
    incident.events = events
    return incident


def test_classify_all_events_updates_orm_events_and_commits():
    incident = _make_incident_with_events(
        [
            _make_orm_event("ListBuckets"),
            _make_orm_event("GetObject"),
        ]
    )
    db = _FakeDB(incident)

    events = classify_all_events(incident.incident_id, db)

    assert events is incident.events
    assert db.commits == 1
    assert incident.events[0].impact_category == "reconnaissance"
    assert incident.events[0].severity_weight == 1
    assert incident.events[1].impact_category == "data_access"
    assert incident.events[1].severity_weight == 3


def test_classify_all_events_applies_bulk_access_rule_to_orm_events():
    incident = _make_incident_with_events(
        [
            _make_orm_event("GetObject", source_ip="9.9.9.9")
            for _ in range(5)
        ]
    )
    db = _FakeDB(incident)

    classify_all_events(incident.incident_id, db)

    assert db.commits == 1
    assert all(event.impact_category == "data_access" for event in incident.events)
    assert all(event.severity_weight == 4 for event in incident.events)


def test_classify_all_events_returns_empty_list_without_commit_when_incident_has_no_events():
    incident = _make_incident_with_events([])
    db = _FakeDB(incident)

    events = classify_all_events(incident.incident_id, db)

    assert events == []
    assert db.commits == 0


def test_classify_all_events_raises_for_missing_incident():
    db = _FakeDB(None)

    with pytest.raises(ValueError, match="Incident not found: missing-incident"):
        classify_all_events("missing-incident", db)
