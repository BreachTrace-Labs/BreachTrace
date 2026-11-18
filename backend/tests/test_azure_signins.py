from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from collectors.azure_signins import SignInCollectionError, collect_signins

APP = '11111111-2222-3333-4444-555555555555'
KEY = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
READER = {'tenant_id': 'tenant', 'client_id': 'reader', 'client_secret': 'secret'}


class Credential:
    def __init__(self, *args): pass
    def get_token(self, scope):
        assert scope == 'https://graph.microsoft.com/.default'
        return SimpleNamespace(token='private-token')
    def close(self): pass


class Client:
    def __init__(self, pages): self.pages, self.calls = list(pages), []
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        page = self.pages.pop(0)
        return SimpleNamespace(status_code=page[0], json=lambda: page[1])


def record(**overrides):
    return {'appId': APP, 'signInEventTypes':['servicePrincipal'], 'createdDateTime':'2026-11-18T11:00:00Z',
            'servicePrincipalCredentialKeyId':KEY, 'status':{'errorCode':0}, 'id':'record',
            'ipAddress':'192.0.2.1', 'resourceDisplayName':'Graph', **overrides}


def test_signin_results_are_bounded_and_matched(monkeypatch):
    monkeypatch.setattr('azure.identity.ClientSecretCredential', Credential)
    other = record(appId='22222222-2222-3333-4444-555555555555')
    rows = [record(), record(servicePrincipalCredentialKeyId='bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'),
            record(servicePrincipalCredentialKeyId=None), other, record(signInEventTypes=['interactiveUser'])]
    client = Client([(200, {'value':rows})])
    result = collect_signins(READER, APP, KEY, now=NOW, client=client)
    assert [row['key_match'] for row in result['events']] == ['matched', 'different_key', 'unavailable']
    assert result['events'][0]['source_ip'] == '192.0.2.1'
    assert result['key_comparison'] == 'operator_reported' and not result['truncated']
    assert 'servicePrincipal' in client.calls[0][1]['params']['$filter']
    assert 'private-token' not in str(result)


def test_signin_permission_denial_and_untrusted_pagination_are_not_empty_success(monkeypatch):
    monkeypatch.setattr('azure.identity.ClientSecretCredential', Credential)
    with pytest.raises(SignInCollectionError, match='access denied'):
        collect_signins(READER, APP, now=NOW, client=Client([(403, {})]))
    client = Client([(200, {'value':[], '@odata.nextLink':'https://evil.example/beta/auditLogs/signIns'})])
    with pytest.raises(SignInCollectionError, match='invalid continuation'):
        collect_signins(READER, APP, now=NOW, client=client)
    assert len(client.calls) == 1


def test_signin_pagination_limit_reports_truncation(monkeypatch):
    monkeypatch.setattr('azure.identity.ClientSecretCredential', Credential)
    next_url = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=next'
    result = collect_signins(READER, APP, now=NOW, client=Client([(200, {'value':[], '@odata.nextLink':next_url})] * 5))
    assert result['truncated'] is True and result['key_comparison'] == 'not_provided'
