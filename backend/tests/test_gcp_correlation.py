from datetime import datetime, timedelta, timezone

from gcp_correlation import correlate_gcp_records
from normalizer.schema import ForensicEvent

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
EMAIL = 'svc@demo-project.iam.gserviceaccount.com'
INVOCATION = 'b0b074ec-2bc6-4a15-abcd-6f456824bc42'


def event(index, *, project='demo-project', principal=EMAIL, op=None, agent=None, offset=0, success=True):
    metadata = {'log_name': f'projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access'}
    if op is not None:
        metadata['operation'] = op
    return ForensicEvent(event_id=f'id-{index}', platform='gcp', timestamp=START + timedelta(seconds=offset),
                         api_action='storage.objects.get', principal_id=principal, user_agent=agent,
                         success=success, raw_data={'_gcp_log_entry': metadata})


def test_provider_operations_group_raw_records_without_removing_evidence():
    rows = [event(1, op={'id': 'op', 'producer': 'storage'}),
            event(2, op={'id': 'op', 'producer': 'storage'}, offset=1, success=False),
            event(3, op={'id': 'op', 'producer': 'other'}), event(4)]
    result = correlate_gcp_records(rows)
    assert (result['raw_record_count'], result['group_count'], result['grouped_record_count'], result['ungrouped_record_count']) == (4, 1, 2, 2)
    group, = result['groups']
    assert group['kind'] == 'provider_operation' and group['confidence'] == 'high'
    assert group['event_ids'] == ['id-1', 'id-2'] and group['failed_count'] == 1
    assert len(rows) == 4


def test_client_invocation_group_is_distinct_and_lower_confidence():
    agent = f'gcloud/500.0.0 (invocation-id/{INVOCATION}; platform/linux)'
    result = correlate_gcp_records([event(1, agent=agent), event(2, agent=agent)])
    assert result['groups'][0]['kind'] == 'client_invocation'
    assert result['groups'][0]['confidence'] == 'medium'


def test_ambiguous_missing_and_conflicting_information_is_not_grouped():
    agent = f'gcloud/500.0 (invocation-id/{INVOCATION})'
    rows = [event(1, agent=agent, project='first'), event(2, agent=agent, project='second'),
            event(3, agent=agent, principal=None), event(4, agent=agent, principal='other@demo-project.iam.gserviceaccount.com'),
            event(5, agent=agent, op={'id': 'incomplete-operation'}),
            event(6, agent=f'other-client (invocation-id/{INVOCATION})'), event(7), event(8)]
    result = correlate_gcp_records(rows)
    assert result['group_count'] == 0 and result['ungrouped_record_count'] == len(rows)


def test_reused_invocation_over_long_period_does_not_create_a_group():
    agent = f'gcloud (invocation-id/{INVOCATION})'
    result = correlate_gcp_records([event(1, agent=agent), event(2, agent=agent, offset=86401)])
    assert result['group_count'] == 0


def test_incident_detail_exposes_group_and_original_records(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from routers.incidents import get_incident_detail
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='svc...',
                                   repo_url='https://github.com/acme/app', commit_hash='a'*40, exposure_start=START)
        incident.status = 'complete'
        db.commit()
        save_forensic_events(db, incident.incident_id, [event(1, op={'id':'same','producer':'storage'}),
                                                        event(2, op={'id':'same','producer':'storage'})])
        db.expire_all()
        detail = get_incident_detail(incident.incident_id, db)
        assert len(detail.events) == 2
        assert detail.gcp_record_correlation['group_count'] == 1
        assert set(detail.gcp_record_correlation['groups'][0]['event_ids']) == {row.event_id for row in detail.events}
