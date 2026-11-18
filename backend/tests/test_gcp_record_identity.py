"""Deduplicate only records with an unambiguous provider identity."""
from datetime import datetime, timezone
from types import SimpleNamespace

from google.api_core.datetime_helpers import DatetimeWithNanoseconds
from sqlalchemy.exc import IntegrityError
import pytest

from collectors.gcp import GCPAuditLogCollector


def entry(*, insert_id='record-1', log_name='projects/p1/logs/audit',
          timestamp='2026-01-01T00:00:00.123456789Z'):
    return SimpleNamespace(insert_id=insert_id, log_name=log_name,
                           timestamp=DatetimeWithNanoseconds.from_rfc3339(timestamp),
                           payload={'methodName': 'storage.objects.get'}, resource=None)


def make_collector(entries):
    instance = object.__new__(GCPAuditLogCollector)
    instance._max_events, instance._page_size, instance._max_window_days = 100, 10, 90
    instance._client = SimpleNamespace(list_entries=lambda **_: iter(entries))
    return instance


def test_deduplicates_only_equal_log_insert_and_full_precision_timestamp():
    items = [entry(), entry(), entry(log_name='projects/p2/logs/audit'),
             entry(insert_id='record-2'), entry(timestamp='2026-01-01T00:00:00.123456788Z')]
    instance = make_collector(items)
    start = datetime(2025, 12, 31, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)
    events = instance.collect('worker@demo-project.iam.gserviceaccount.com', start, end)
    assert len(events) == 4
    assert len({event.source_record_id for event in events}) == 4
    assert events[0].raw_data['_gcp_log_entry']['timestamp_precise'].endswith('.123456789Z')


@pytest.mark.parametrize('field', ['insert_id', 'log_name'])
def test_missing_provider_identifiers_preserve_each_record(field):
    items = [entry(**{field: None}), entry(**{field: None})]
    instance = make_collector(items)
    start = datetime(2025, 12, 31, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)
    events = instance.collect('worker@demo-project.iam.gserviceaccount.com', start, end)
    assert len(events) == 2 and all(event.source_record_id is None for event in events)


def test_repeated_saves_are_idempotent_per_incident_and_preserve_cross_incident_evidence(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from db.models import ForensicEvent
    with sqlite_factory() as db:
        def incident(sha):
            return create_incident(db, credential_type='gcp_service_account', credential_hint='svc...',
                                   repo_url='https://github.com/acme/app', commit_hash=sha,
                                   exposure_start=datetime(2026, 1, 1, tzinfo=timezone.utc))
        first, second = incident('a' * 40), incident('b' * 40)
        collector = make_collector([])
        mapped = lambda: collector._map_entry(entry())
        assert len(save_forensic_events(db, first.incident_id, [mapped(), mapped()])) == 1
        assert len(save_forensic_events(db, first.incident_id, [mapped()])) == 0
        assert len(save_forensic_events(db, second.incident_id, [mapped()])) == 1
        assert db.query(ForensicEvent).count() == 2
        original = db.query(ForensicEvent).filter_by(incident_id=first.incident_id).one()
        db.add(ForensicEvent(event_id='independent-id', incident_id=first.incident_id, platform='gcp',
                             source_record_id=original.source_record_id, timestamp=original.timestamp,
                             api_action=original.api_action, success=True, raw_data={}))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()
