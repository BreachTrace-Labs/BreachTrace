"""A failed refresh must not erase the last successful forensic evidence."""
from datetime import datetime, timezone

import pytest

from db.crud import create_incident, save_forensic_events
from db.models import CollectionStatus, ForensicEvent as StoredEvent, IncidentRecord
from normalizer.schema import ForensicEvent


def _incident(factory):
    with factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='worker...',
                                   principal_id='worker@demo-project.iam.gserviceaccount.com',
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40,
                                   exposure_start=datetime.now(timezone.utc))
        incident.status = 'complete'
        incident.report_text = 'Previous evidence-backed report'
        incident.overall_severity = 3
        db.commit()
        save_forensic_events(db, incident.incident_id, [ForensicEvent(
            event_id='old-event', platform='gcp', timestamp=datetime.now(timezone.utc),
            api_action='storage.objects.get', success=True)])
        return incident.incident_id, incident.exposure_start


@pytest.mark.parametrize('failure', ['collection', 'persistence'])
def test_failed_refresh_retains_previous_evidence(sqlite_factory, monkeypatch, failure):
    import pipeline
    incident_id, start = _incident(sqlite_factory)
    monkeypatch.setattr(pipeline, 'SessionLocal', sqlite_factory)

    class Collector:
        def collect(self, **kwargs):
            if failure == 'collection':
                raise PermissionError('private provider response')
            return [ForensicEvent(event_id='new-event', platform='gcp', timestamp=datetime.now(timezone.utc),
                                  api_action='storage.objects.list', success=True)]

    monkeypatch.setitem(pipeline._COLLECTOR_MAP, 'gcp', Collector)
    if failure == 'persistence':
        def fail_write(db, incident_id, events):
            raise RuntimeError('database failure')
        monkeypatch.setattr(pipeline, 'save_forensic_events', fail_write)
    pipeline.run_collection_pipeline(incident_id, 'worker@demo-project.iam.gserviceaccount.com', start,
                                     platform='gcp', refresh_existing=True)
    with sqlite_factory() as db:
        incident = db.get(IncidentRecord, incident_id)
        assert incident.status == 'error'
        assert incident.report_text == 'Previous evidence-backed report'
        assert incident.overall_severity == 3
        assert [event.event_id for event in db.query(StoredEvent).all()] == ['old-event']
        if failure == 'collection':
            status = db.query(CollectionStatus).one()
            assert status.status == 'error' and 'private provider response' not in status.error_message


def test_successful_empty_refresh_replaces_previous_evidence(sqlite_factory, monkeypatch):
    import pipeline
    incident_id, start = _incident(sqlite_factory)
    monkeypatch.setattr(pipeline, 'SessionLocal', sqlite_factory)
    monkeypatch.setattr(pipeline, '_index_incident_safely', lambda *_: None)
    monkeypatch.setattr(pipeline, '_upgrade_report', lambda *_: False)
    class Collector:
        def collect(self, **kwargs):
            return []
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, 'gcp', Collector)
    pipeline.run_collection_pipeline(incident_id, 'worker@demo-project.iam.gserviceaccount.com', start,
                                     platform='gcp', refresh_existing=True)
    with sqlite_factory() as db:
        assert db.get(IncidentRecord, incident_id).status == 'complete'
        assert db.query(StoredEvent).count() == 0
        assert db.query(CollectionStatus).one().status == 'no_activity'
