from types import SimpleNamespace

from gcp_attribution import event_attribution, key_digest

EMAIL = 'svc@demo.iam.gserviceaccount.com'
KEY = 'a' * 40
OTHER = 'b' * 40


def event(key=KEY, email=EMAIL, principal=EMAIL):
    return SimpleNamespace(platform='gcp', raw_data={'authenticationInfo': {
        'principalEmail': principal,
        'serviceAccountKeyName': f'//iam.googleapis.com/projects/demo/serviceAccounts/{email}/keys/{key}'}})


def test_matching_requires_exact_key_and_consistent_service_account():
    incident = SimpleNamespace(principal_id=EMAIL)
    association = SimpleNamespace(key_digest=key_digest(KEY))
    assert event_attribution(event(), incident, association) == 'matched'
    assert event_attribution(event(OTHER), incident, association) == 'different_key'
    assert event_attribution(event(email='other@demo.iam.gserviceaccount.com'), incident, association) == 'unavailable'
    assert event_attribution(event(principal='other@demo.iam.gserviceaccount.com'), incident, association) == 'unavailable'
    assert event_attribution(event(key='not-a-key'), incident, association) == 'unavailable'
    assert event_attribution(SimpleNamespace(platform='gcp', raw_data={}), incident, association) == 'unavailable'
    assert event_attribution(event(), incident, None) is None
