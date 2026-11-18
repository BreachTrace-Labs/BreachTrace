from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from scorer.compliance import compliance_review_flags


def sample(category, resource=None):
    return SimpleNamespace(impact_category=category, affected_resource=resource)


def ids(flags):
    return {item['id'] for item in flags}


def test_detection_only_prompts_nhi_review_without_assuming_other_scope():
    flags = compliance_review_flags('github_pat', [sample('financial_abuse')], forensic_tier=2)
    assert ids(flags) == {'owasp-nhi2'}
    assert 'if it belongs' in flags[0]['reason']


def test_payment_classification_does_not_claim_personal_data_or_pci_scope():
    flags = compliance_review_flags('stripe_secret_key', [sample('financial_abuse')])
    assert ids(flags) == {'owasp-nhi2', 'pci-incident-response'}
    assert 'does not establish' in next(x for x in flags if x['id'] == 'pci-incident-response')['reason']


def test_independent_signals_follow_evidence():
    flags = compliance_review_flags('aws_access_key', [sample('data_access', 'customer-records'), sample('privilege_escalation')])
    assert ids(flags) == {'owasp-nhi2', 'gdpr-32-33', 'soc2-security'}
    assert 'name alone' in next(x for x in flags if x['id'] == 'gdpr-32-33')['reason']


def test_detail_ignores_stale_combined_flag_and_outside_window_events(sqlite_factory):
    from db.crud import create_incident, save_forensic_events
    from normalizer.schema import ForensicEvent
    from routers.incidents import get_incident_detail
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with sqlite_factory() as db:
        inc = create_incident(db, credential_type='stripe_secret_key', credential_hint='sk_test_****test', repo_url='https://github.com/acme/app', commit_hash='a'*40, exposure_start=start)
        inc.status = 'complete'; inc.gdpr_flag = True; db.commit()
        save_forensic_events(db, inc.incident_id, [ForensicEvent(timestamp=start-timedelta(seconds=1), platform='stripe', api_action='charge.succeeded', impact_category='financial_abuse', severity_weight=2)])
        db.expire_all()
        result = get_incident_detail(inc.incident_id, db)
        assert result.gdpr_flag is False and result.pcidss_flag is False
        assert ids(result.compliance_review_flags) == {'owasp-nhi2'}
