from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from scorer.blast_radius import dynamic_blast_radius

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(action, *, platform='aws', offset=0, success=True, category='reconnaissance', weight=1, resource='bucket'):
    return SimpleNamespace(timestamp=START + timedelta(seconds=offset), platform=platform, api_action=action,
                           success=success, impact_category=category, severity_weight=weight, affected_resource=resource)


def assess(events, **kwargs):
    return dynamic_blast_radius(events, START, forensic_tier=kwargs.get('tier', 1),
                                incident_status=kwargs.get('status', 'complete'),
                                collection_status=kwargs.get('collection', 'success'))


def test_dynamic_assessment_tracks_successful_actions_and_denied_attempts():
    rows = [event('before', offset=-1, category='privilege_escalation', weight=4),
            event('ListBuckets'), event('CreateKey', success=False, category='privilege_escalation', weight=4),
            event('charge.created', platform='stripe', category='financial_abuse', weight=2, resource='charge')]
    result = assess(rows)
    assert result['severity'] == 'HIGH'
    assert (result['event_count'], result['successful_count'], result['failed_count'], result['resource_count']) == (3, 2, 1, 2)
    assert [entry['platform'] for entry in result['platforms']] == ['aws', 'stripe']
    assert result['platforms'][0]['actions'] == [{'action': 'ListBuckets', 'count': 1}]
    assert result['last_observed_at'] == START
    rows.append(event('CreateAccessKey', category='privilege_escalation', weight=4, offset=5))
    assert assess(rows)['severity'] == 'CRITICAL'


def test_unassessed_empty_failed_and_in_progress_are_not_low_severity():
    assert assess([], tier=2)['status'] == 'unavailable'
    assert assess([], collection='no_activity')['status'] == 'no_observed_activity'
    assert assess([], status='error', collection='error')['status'] == 'error'
    assert assess([], status='collecting', collection=None)['status'] == 'collecting'
    denied = assess([event('Denied', success=False, category='privilege_escalation', weight=4)])
    assert denied['severity'] is None and denied['failed_count'] == 1


def test_recorded_end_limits_the_observed_window_inclusively():
    rows = [event('before', offset=-1), event('during', offset=0), event('at_end', offset=10),
            event('after', offset=11, category='privilege_escalation', weight=4)]
    result = dynamic_blast_radius(rows, START, exposure_end=START + timedelta(seconds=10),
                                  forensic_tier=1, incident_status='complete', collection_status='success')
    assert result['event_count'] == 2 and result['severity'] == 'LOW'
    assert [action['action'] for action in result['platforms'][0]['actions']] == ['at_end', 'during']


def test_detail_recalculates_after_new_stored_events(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from normalizer.schema import ForensicEvent
    from routers.incidents import get_incident_detail

    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='aws_access_key', credential_hint='AKIA****TEST',
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40, exposure_start=START)
        incident.status = 'complete'
        db.commit()
        def store(action, category, weight):
            save_forensic_events(db, incident.incident_id, [ForensicEvent(timestamp=START, platform='aws',
                api_action=action, success=True, impact_category=category, severity_weight=weight)])
            db.expire_all()
        store('ListBuckets', 'reconnaissance', 1)
        assert get_incident_detail(incident.incident_id, db).dynamic_blast_radius['severity'] == 'LOW'
        store('CreateAccessKey', 'privilege_escalation', 4)
        updated = get_incident_detail(incident.incident_id, db).dynamic_blast_radius
        assert updated['severity'] == 'CRITICAL' and updated['successful_count'] == 2


def test_financial_activity_scopes_history_and_exposure_window(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from normalizer.schema import ForensicEvent
    from routers.incidents import get_incident_detail
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='stripe_secret_key', credential_hint='sk_test_****test',
            repo_url='https://github.com/acme/app', commit_hash='a' * 40, exposure_start=START)
        incident.status = 'complete'
        incident.financial_impact = 'stale stored summary'
        incident.exposure_end = START + timedelta(seconds=10)
        db.commit()
        events = [ForensicEvent(timestamp=START + timedelta(seconds=offset), platform='stripe',
            api_action='charge.succeeded', success=True, raw_data={'data': {'object': {'id': key, 'amount': amount, 'currency': 'usd'}}})
            for offset, key, amount in [(-1, 'ch_before', 1000), (5, 'ch_inside', 2000), (11, 'ch_after', 3000)]]
        save_forensic_events(db, incident.incident_id, events)
        db.expire_all()
        response = get_incident_detail(incident.incident_id, db)
        assert response.financial_impact_lines[0].amount == 20
        assert response.financial_history_lines[0].amount == 60
        assert response.dynamic_blast_radius['event_count'] == 1
        incident = db.get(type(incident), incident.incident_id)
        incident.exposure_start = START + timedelta(days=1)
        db.commit(); db.expire_all()
        response = get_incident_detail(incident.incident_id, db)
        assert response.financial_impact_lines == []
        assert response.financial_history_lines[0].amount == 60
        assert response.dynamic_blast_radius['event_count'] == 0
