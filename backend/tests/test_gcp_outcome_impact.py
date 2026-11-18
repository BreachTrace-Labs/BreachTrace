"""An attempted GCP operation must not be reported as completed impact."""
from datetime import datetime, timezone

from normalizer.schema import ForensicEvent
from reporter.compose import deterministic_sections
from reporter.facts import build_fact_sheet
from reporter.validate import validate_sections
from scorer.compliance import compliance_review_flags
from scorer.severity import (check_gdpr_flag, check_pcidss_flag, check_soc2_flag,
                             compute_financial_impact_lines, score_incident)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(action, category, *, success, resource='customer-payment-backup', weight=4):
    return ForensicEvent(platform='gcp', timestamp=NOW, api_action=action,
                         impact_category=category, severity_weight=weight,
                         success=success, affected_resource=resource)


def facts(events):
    return build_fact_sheet(events, platform='gcp', overall_severity=score_incident(events),
                            exposure_duration_seconds=10, credential_type='gcp_service_account')


def test_failed_operations_do_not_prove_impact_but_remain_visible():
    events = [event('storage.objects.get', 'data_access', success=False),
              event('compute.instances.insert', 'resource_abuse', success=False),
              event('SetIamPolicy', 'privilege_escalation', success=False)]
    assert score_incident(events) == 'Low'
    assert compute_financial_impact_lines(events) == []
    assert not check_gdpr_flag(events) and not check_pcidss_flag(events) and not check_soc2_flag(events)
    assert {flag['id'] for flag in compliance_review_flags('gcp_service_account', events)} == {'owasp-nhi2'}
    sheet = facts(events)
    assert sheet['event_count'] == sheet['failed_count'] == 3
    assert sheet['categories'] == {} and sheet['resources'] == []
    sections = deterministic_sections(sheet)
    assert 'All recorded operations failed' in sections['executive_summary']
    assert all('Attempted' in line and 'failed' in line for line in sections['narrative'])


def test_mixed_success_and_failure_only_counts_successful_resource_impact():
    events = [event('storage.objects.get', 'data_access', success=False, resource='customer-payment-failed'),
              event('storage.objects.get', 'data_access', success=True, resource='public-readme', weight=2)]
    sheet = facts(events)
    assert sheet['categories'] == {'data_access': 1}
    assert sheet['actions'][0]['count'] == 2 and sheet['actions'][0]['failed'] == 1
    assert sheet['resources'] == ['public-readme'] and sheet['actions'][0]['resources'] == ['public-readme']
    assert not check_gdpr_flag(events) and not check_pcidss_flag(events)


def test_successful_gcp_action_still_contributes_to_impact():
    events = [event('SetIamPolicy', 'privilege_escalation', success=True)]
    assert score_incident(events) == 'Critical' and check_soc2_flag(events)
    assert facts(events)['categories'] == {'privilege_escalation': 1}


def test_model_report_must_acknowledge_when_all_gcp_events_failed():
    sheet = facts([event('SetIamPolicy', 'privilege_escalation', success=False)])
    sections = {'executive_summary': 'A policy was changed.', 'narrative': ['A policy was modified.'], 'business_impact': ''}
    assert any('must state' in issue for issue in validate_sections(sections, sheet))


def test_gcp_with_failed_events_keeps_the_deterministic_report(monkeypatch):
    from reporter import writers
    monkeypatch.setattr(writers, '_writers', lambda: (_ for _ in ()).throw(AssertionError('model must not run')))
    assert writers.upgrade_report(facts([event('SetIamPolicy', 'privilege_escalation', success=False)])) is None


def test_incident_detail_does_not_infer_compliance_or_cost_from_failed_gcp_operations(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from routers.incidents import get_incident_detail
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='svc...',
                                   repo_url='https://github.com/example/repo', commit_hash='a' * 40, exposure_start=NOW)
        incident.status = 'complete'
        db.commit()
        save_forensic_events(db, incident.incident_id, [event('compute.instances.insert', 'resource_abuse', success=False),
                                                        event('storage.objects.get', 'data_access', success=False)])
        db.expire_all()
        result = get_incident_detail(incident.incident_id, db)
        assert not result.gdpr_flag and not result.pcidss_flag and not result.soc2_flag
        assert result.financial_impact_lines == []
        assert result.dynamic_blast_radius['event_count'] == 2 and result.dynamic_blast_radius['failed_count'] == 2


def test_gcp_detail_does_not_return_a_stale_guessed_financial_summary(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from routers.incidents import get_incident_detail
    with sqlite_factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='svc...',
                                   repo_url='https://github.com/example/repo', commit_hash='a' * 40, exposure_start=NOW)
        incident.status = 'complete'
        incident.financial_impact = 'Compute Engine: assumed estimate'
        db.commit()
        save_forensic_events(db, incident.incident_id, [event('compute.instances.insert', 'resource_abuse', success=True)])
        db.expire_all()
        detail = get_incident_detail(incident.incident_id, db)
        assert detail.estimated_financial_impact is None
        assert detail.financial_impact_lines == [] and detail.financial_history_lines == []
        assert facts([event('compute.instances.insert', 'resource_abuse', success=True)])['financial_limit']
