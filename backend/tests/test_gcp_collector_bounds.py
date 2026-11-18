"""Cloud Logging queries must be bounded and must not hide partial results."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from collectors.gcp import GCPAuditLogCollector

PRINCIPAL = 'worker@demo-project.iam.gserviceaccount.com'
START = datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


def collector(entries, limit=2):
    instance = object.__new__(GCPAuditLogCollector)
    instance._max_events, instance._page_size, instance._max_window_days = limit, 2, 90
    class Client:
        def list_entries(self, **kwargs):
            self.kwargs = kwargs
            return iter(entries)
    instance._client = Client()
    return instance


def entry(index):
    return SimpleNamespace(timestamp=START + timedelta(seconds=index),
                           payload={'methodName': 'storage.objects.get'}, resource=None)


def test_query_is_principal_scoped_ordered_and_preserves_microseconds():
    instance = collector([entry(0), entry(1)])
    events = instance.collect(PRINCIPAL, START, START + timedelta(hours=1))
    assert len(events) == 2
    args = instance._client.kwargs
    assert args['page_size'] == 2 and args['order_by'] == 'timestamp asc'
    assert f'principalEmail="{PRINCIPAL}"' in args['filter_']
    assert '2026-01-01T12:00:00.123456Z' in args['filter_']
    assert 'cloudaudit.googleapis.com' in args['filter_']


def test_event_limit_fails_instead_of_returning_a_partial_timeline():
    with pytest.raises(ValueError, match='collection limit exceeded'):
        collector([entry(0), entry(1), entry(2)]).collect(PRINCIPAL, START, START + timedelta(hours=1))


def test_no_results_and_provider_failure_are_distinct():
    assert collector([]).collect(PRINCIPAL, START, START) == []
    def failed():
        yield entry(0)
        raise RuntimeError('provider failed')
    with pytest.raises(RuntimeError, match='provider failed'):
        collector(failed()).collect(PRINCIPAL, START, START + timedelta(hours=1))


@pytest.mark.parametrize('principal', ['', 'x" OR severity>=ERROR', 'AIza' + 'a' * 35])
def test_unverified_principal_never_becomes_a_logging_filter(principal):
    instance = collector([])
    with pytest.raises(ValueError, match='valid GCP service-account'):
        instance.collect(principal, START, START)
    assert not hasattr(instance._client, 'kwargs')


def test_invalid_or_excessive_windows_are_rejected():
    instance = collector([])
    with pytest.raises(ValueError, match='end must not precede'):
        instance.collect(PRINCIPAL, START, START - timedelta(seconds=1))
    with pytest.raises(ValueError, match='window exceeds'):
        instance.collect(PRINCIPAL, START, START + timedelta(days=91))


@pytest.mark.parametrize('result', ['success', 'collection_failure', 'cleanup_failure'])
def test_pipeline_closes_gcp_collector_on_success_and_failure(sqlite_factory, monkeypatch, result, caplog):
    import pipeline
    from db.crud import create_incident
    from db.models import IncidentRecord
    closed = []
    class Collector:
        def collect(self, **kwargs):
            if result == 'collection_failure':
                raise RuntimeError('private provider response')
            return []
        def close(self):
            closed.append(True)
            if result == 'cleanup_failure':
                raise RuntimeError('private cleanup response')
    monkeypatch.setattr(pipeline, 'SessionLocal', sqlite_factory)
    monkeypatch.setattr(pipeline, '_index_incident_safely', lambda *_: None)
    monkeypatch.setattr(pipeline, '_upgrade_report', lambda *_: False)
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, 'gcp', Collector)
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='worker...',
                                   principal_id=PRINCIPAL, repo_url='https://github.com/acme/app',
                                   commit_hash='a' * 40, exposure_start=START)
        incident_id = incident.incident_id
    pipeline.run_collection_pipeline(incident_id, PRINCIPAL, START, platform='gcp')
    assert closed == [True]
    with sqlite_factory() as db:
        assert db.get(IncidentRecord, incident_id).status == ('error' if result == 'collection_failure' else 'complete')
    assert 'private provider response' not in caplog.text
    assert 'private cleanup response' not in caplog.text


def test_gcp_collector_close_releases_client():
    instance = collector([])
    closed = []
    instance._client.close = lambda: closed.append(True)
    instance.close()
    assert closed == [True]


@pytest.mark.parametrize('kind,expected', [('limit', 'collection limit exceeded'), ('permission', 'authentication or log access failed')])
def test_pipeline_records_gcp_failures_without_provider_details(sqlite_factory, monkeypatch, kind, expected):
    import pipeline
    from db.crud import create_incident
    from db.models import CollectionStatus, IncidentRecord
    class Forbidden(Exception):
        pass
    class Collector:
        def collect(self, **kwargs):
            if kind == 'limit':
                raise ValueError('GCP audit log collection limit exceeded; narrow the time window')
            raise Forbidden('sensitive provider response')
    monkeypatch.setattr(pipeline, 'SessionLocal', sqlite_factory)
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, 'gcp', Collector)
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='worker...',
                                   principal_id=PRINCIPAL, repo_url='https://github.com/acme/app',
                                   commit_hash='a' * 40, exposure_start=START)
        incident_id = incident.incident_id
    pipeline.run_collection_pipeline(incident_id, PRINCIPAL, START, platform='gcp')
    with sqlite_factory() as db:
        status = db.query(CollectionStatus).filter_by(incident_id=incident_id).one()
        assert status.status == 'error' and status.event_count == 0
        assert expected in status.error_message and 'sensitive provider response' not in status.error_message
        assert db.get(IncidentRecord, incident_id).status == 'error'
