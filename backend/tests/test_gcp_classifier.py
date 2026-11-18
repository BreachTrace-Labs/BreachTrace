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


@pytest.mark.parametrize('method,category', [
    ('storage.buckets.list', 'reconnaissance'), ('storage.buckets.get', 'reconnaissance'),
    ('storage.objects.list', 'reconnaissance'), ('storage.buckets.getStorageLayout', 'reconnaissance'),
    ('storage.objects.get', 'data_access'), ('storage.objects.create', 'resource_abuse'),
    ('storage.objects.copy', 'resource_abuse'), ('billing.budgets.update', 'resource_abuse'),
    ('compute.snapshots.insert', 'resource_abuse'), ('logging.sinks.create', 'resource_abuse'),
])
def test_scenario_operations_do_not_infer_data_theft_or_financial_abuse(method, category):
    assert classify_event(_make_gcp_event(method)).impact_category == category


@pytest.mark.parametrize('service,action', [
    ('secretmanager.googleapis.com', 'google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion'),
    ('cloudkms.googleapis.com', 'Decrypt'),
])
def test_documented_service_scoped_aliases_are_classified_without_rewriting_action(service, action):
    event = _make_gcp_event(action)
    event.event_source = service
    classify_event(event)
    assert event.impact_category == 'data_access' and event.api_action == action
    event.event_source = 'unrelated.googleapis.com'
    classify_event(event)
    assert event.impact_category is None and event.severity_weight is None


@pytest.mark.parametrize('service,action,category', [
    ('compute.googleapis.com', 'v1.compute.instances.insert', 'resource_abuse'),
    ('compute.googleapis.com', 'beta.compute.instances.stop', 'resource_abuse'),
    ('iam.googleapis.com', 'google.iam.admin.v1.CreateServiceAccountKey', 'privilege_escalation'),
    ('iam.googleapis.com', 'google.iam.admin.v1.CreateServiceAccount', 'privilege_escalation'),
])
def test_provider_audit_method_aliases_are_scoped(service, action, category):
    event = _make_gcp_event(action)
    event.event_source = service
    assert classify_event(event).impact_category == category
    event.event_source = 'unrelated.googleapis.com'
    assert classify_event(event).impact_category is None


def test_classification_coverage_does_not_conflate_unclassified_with_uncollected(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from routers.incidents import get_incident_detail
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='svc...',
                                   repo_url='https://github.com/acme/app', commit_hash='a'*40,
                                   exposure_start=datetime(2026, 1, 1, tzinfo=timezone.utc))
        incident.status = 'complete'
        db.commit()
        records = classify_events([_make_gcp_event('storage.buckets.list'), _make_gcp_event('unknown.api.method')])
        save_forensic_events(db, incident.incident_id, records)
        db.expire_all()
        result = get_incident_detail(incident.incident_id, db)
        assert result.gcp_classification_coverage == {'record_count': 2, 'classified_count': 1, 'unclassified_count': 1}
        assert len(result.events) == 2


def test_pipeline_does_not_report_low_severity_when_only_gcp_actions_are_unclassified(sqlite_factory, monkeypatch):
    import pipeline
    from db.crud import create_incident
    from db.models import IncidentRecord
    class Collector:
        def collect(self, **kwargs):
            return [_make_gcp_event('unknown.api.method')]
    monkeypatch.setattr(pipeline, 'SessionLocal', sqlite_factory)
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, 'gcp', Collector)
    monkeypatch.setattr(pipeline, '_index_incident_safely', lambda *_: None)
    monkeypatch.setattr(pipeline, '_upgrade_report', lambda *_: False)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='svc...',
                                   principal_id='svc@demo-project.iam.gserviceaccount.com',
                                   repo_url='https://github.com/acme/app', commit_hash='a'*40, exposure_start=start)
        incident_id = incident.incident_id
    pipeline.run_collection_pipeline(incident_id, 'svc@demo-project.iam.gserviceaccount.com', start, platform='gcp')
    with sqlite_factory() as db:
        result = db.get(IncidentRecord, incident_id)
        assert result.status == 'complete' and result.overall_severity is None
        assert 'Overall severity: Unknown.' in result.report_text


# ---------------------------------------------------------------------------
# Unknown operations remain visible without assigning a guessed category.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "api_action",
    [
        "someservice.resource.list", "someservice.resource.get", "someservice.resource.create",
        "someservice.resource.delete", "someservice.resource.setIamPolicy", "someservice.resource.unknownverb",
    ],
)
def test_unknown_gcp_methods_remain_unclassified(api_action):
    event = classify_event(_make_gcp_event(api_action))
    assert event.impact_category is None
    assert event.severity_weight is None


# ---------------------------------------------------------------------------
# Generic bulk escalation is not evidence of GCP exfiltration.
# ---------------------------------------------------------------------------

def test_repeated_gcp_reads_are_not_automatically_called_exfiltration():
    # bigquery.tables.getData must classify as data_access initially (taxonomy required)
    events = [
        _make_gcp_event("bigquery.tables.getData", source_ip="9.9.9.9")
        for _ in range(5)
    ]
    classify_events(events)
    assert all(e.impact_category == "data_access" for e in events)


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
        _make_gcp_event("storage.buckets.list"),                # reconnaissance
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
    event = _make_gcp_event("storage.buckets.list")
    result = classify_event(event)
    assert result is event
    assert event.impact_category is not None
