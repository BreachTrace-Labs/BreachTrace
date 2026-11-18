"""Synthetic Twilio detection, scoping, evidence and cost regression checks."""
from datetime import datetime, timedelta, timezone
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from classifier.rules import classify_events
from collectors.twilio import TwilioUsageCollector
from detector.match_resolver import resolve_match
from detector.scanner import scan, scan_text
from normalizer.schema import ForensicEvent
from scorer.severity import compute_financial_impact_lines

ACCOUNT = 'AC3f9a1c7e5b2d4086a9f1e3c5b7d92a4e'
KEY = 'SK45b87d21e9c31a5d8f64c09e2b7a634f'
SECRET = 'syntheticSecretX8F7G6H5J4K3L2Q1'
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_api_key_detection_without_account_is_detection_only_and_masked():
    text = f'TWILIO_API_KEY_SID={KEY}\nTWILIO_API_KEY_SECRET={SECRET}'
    match = next(x for x in scan_text(text) if x.credential_type == 'twilio_api_key')
    resolved = resolve_match(match)
    assert resolved.platform == 'twilio' and resolved.forensic_tier == 2
    assert resolved.credential is None and SECRET not in repr(match) and KEY not in repr(match)


def test_api_key_with_nearby_account_is_scoped_to_that_account():
    text = f'TWILIO_ACCOUNT_SID={ACCOUNT}\nTWILIO_API_KEY_SID={KEY}\nTWILIO_API_KEY_SECRET={SECRET}'
    match = next(x for x in scan_text(text) if x.credential_type == 'twilio_api_key')
    assert resolve_match(match).credential == ACCOUNT
    assert resolve_match(match).forensic_tier == 1


def test_api_key_diff_does_not_use_deleted_or_other_file_context():
    text = f'diff --git a/a b/a\n@@ -1 +1 @@\n-TWILIO_ACCOUNT_SID={ACCOUNT}\n+TWILIO_API_KEY_SID={KEY}\n'
    match = next(x for x in scan(text, include_saas=True) if x.credential_type == 'twilio_api_key')
    assert resolve_match(match).forensic_tier == 2


def test_collector_scopes_exact_window_and_redacts_monitor_data(monkeypatch):
    client = MagicMock()
    account = client.api.v2010.accounts.return_value
    message = SimpleNamespace(sid='SM123', direction='outbound-api', date_sent=None,
                              date_created=START, status='queued', account_sid=ACCOUNT,
                              body='secret body', to='+15551234567', from_='+15557654321',
                              price=None, price_unit=None)
    outside = SimpleNamespace(**{**vars(message), 'date_created': START - timedelta(seconds=1)})
    monitor = SimpleNamespace(event_date=START + timedelta(seconds=1), account_sid=ACCOUNT,
                              sid='AE123', event_type='account-api-keys.created', actor_sid='US123',
                              resource_sid='SK123', resource_type='account-api-keys',
                              source_ip_address='192.0.2.7', actor_type='user', source='web',
                              event_data={'secret': SECRET}, description=SECRET)
    account.messages.list.return_value = [message, outside]
    account.calls.list.return_value = []
    client.monitor.v1.events.list.return_value = [monitor]
    sdk = types.ModuleType('twilio')
    rest = types.ModuleType('twilio.rest')
    rest.Client = lambda *args, **kwargs: client
    sdk.rest = rest
    monkeypatch.setitem(sys.modules, 'twilio', sdk)
    monkeypatch.setitem(sys.modules, 'twilio.rest', rest)
    collector = TwilioUsageCollector(account_sid=ACCOUNT, auth_token='synthetic')
    events = collector.collect(ACCOUNT, START, START + timedelta(minutes=1))
    assert [e.api_action for e in events] == ['message.queued', 'api_key.created']
    assert events[1].source_ip == '192.0.2.7' and events[1].principal_id == 'US123'
    assert SECRET not in str(events) and 'secret body' not in str(events)
    with pytest.raises(ValueError, match='different account'):
        collector.collect('AC' + '1' * 32, START, START)


def test_price_currency_and_pending_are_kept_separate():
    events = [ForensicEvent(platform='twilio', timestamp=START, api_action='message.sent',
              raw_data={'price': price, 'price_unit': unit})
              for price, unit in [(0.1, 'usd'), (0.2, 'eur'), (None, 'usd')]]
    lines = compute_financial_impact_lines(events)
    assert {(line.currency, line.amount, line.actual) for line in lines} == {
        ('USD', 0.1, True), ('EUR', 0.2, True), (None, None, False)}


def test_bulk_escalation_uses_distinct_message_sids_and_keeps_category():
    events = [ForensicEvent(platform='twilio', timestamp=START, api_action='message.sent', principal_id=ACCOUNT,
              raw_data={'sid': f'SM{i}', 'direction': 'outbound-api'}) for i in range(20)]
    classify_events(events)
    assert all(e.severity_weight == 4 and e.impact_category == 'communication_abuse' and e.source_ip is None for e in events)
    repeated = [events[0].model_copy(deep=True) for _ in range(20)]
    classify_events(repeated)
    assert all(e.severity_weight == 2 for e in repeated)


def test_operator_associates_only_configured_account_and_queues_collection(sqlite_factory, monkeypatch):
    import config
    from fastapi import BackgroundTasks, HTTPException
    from db.crud import create_incident, finalize_non_forensic_incident
    from routers.incidents import TwilioAccountRequest, associate_twilio_account

    db = sqlite_factory()
    incident = create_incident(db, credential_type='twilio_api_key', credential_hint='SK45****634f',
                               access_key_id=None, repo_url='https://github.com/example/repo',
                               commit_hash='synthetic', exposure_start=START,
                               principal_id=None, forensic_tier=2)
    finalize_non_forensic_incident(db, incident.incident_id, 'Account unknown')
    monkeypatch.setattr(config, 'TWILIO_ACCOUNT_SID', ACCOUNT)
    tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        associate_twilio_account(incident.incident_id, TwilioAccountRequest(account_sid='AC' + '1' * 32), tasks, None, db)
    assert exc.value.status_code == 400
    assert incident.forensic_tier == 2 and incident.principal_id is None and not _queued(db)
    result = associate_twilio_account(incident.incident_id, TwilioAccountRequest(account_sid=ACCOUNT), tasks, None, db)
    assert result.status == 'collecting' and incident.principal_id == ACCOUNT
    assert incident.forensic_tier == 1 and _queued(db) == 1


def _queued(db):
    from db.models import BackgroundJob
    return db.query(BackgroundJob).filter_by(kind='incident_collect').count()


def test_monitor_permission_failure_is_not_a_successful_empty_result(monkeypatch):
    client = MagicMock()
    account = client.api.v2010.accounts.return_value
    account.messages.list.return_value = []
    account.calls.list.return_value = []
    client.monitor.v1.events.list.side_effect = PermissionError('denied')
    sdk = types.ModuleType('twilio')
    rest = types.ModuleType('twilio.rest')
    rest.Client = lambda *args, **kwargs: client
    sdk.rest = rest
    monkeypatch.setitem(sys.modules, 'twilio', sdk)
    monkeypatch.setitem(sys.modules, 'twilio.rest', rest)
    collector = TwilioUsageCollector(account_sid=ACCOUNT, auth_token='synthetic')
    monkeypatch.setattr(collector, '_list_monitor', lambda *_: (_ for _ in ()).throw(PermissionError('denied')))
    with pytest.raises(PermissionError):
        collector.collect(ACCOUNT, START, START + timedelta(minutes=1))
