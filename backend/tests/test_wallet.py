"""Wallet encryption, access boundaries, verification, and replacement."""
import pytest
from fastapi.testclient import TestClient

from db.database import get_db
from db.models import AuditLog, CredentialWalletEntry


@pytest.fixture
def wallet_client(sqlite_factory, monkeypatch):
    monkeypatch.setenv('JWT_SECRET_KEY', 'x' * 64)
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    monkeypatch.setenv('BREACHTRACE_LOCAL_TEST_MODE', 'true')
    import wallet_verify
    monkeypatch.setattr(wallet_verify, 'SessionLocal', sqlite_factory)
    checks = []
    monkeypatch.setattr(wallet_verify, '_check', lambda provider, values: checks.append((provider, values)))
    from main import app
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[get_db] = database
    yield TestClient(app), sqlite_factory, checks
    app.dependency_overrides.clear()


def test_wallet_lifecycle_and_role_boundaries(wallet_client):
    client, factory, checks = wallet_client
    response = client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com',
                           'admin_password':'admin password','admin_full_name':'Admin'})
    assert response.status_code == 201
    def login(email, password):
        response = client.post('/auth/token', data={'username':email, 'password':password})
        return {'Authorization':'Bearer ' + response.json()['access_token']}
    admin = login('admin@example.com','admin password')
    project = client.post('/projects', headers=admin, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    path = f'/projects/{project}/wallet'
    fake_key = 'rk_test_fakeKeyForTesting123'
    assert client.get(path).status_code == 401
    result = client.post(path, headers=admin, json={'provider':'stripe','label':'Reader','credentials':{'api_key':fake_key}})
    assert result.status_code == 202
    assert fake_key not in result.text
    entries = client.get(path, headers=admin).json()
    assert len(entries) == 1 and entries[0]['verification_status'] == 'ok'
    assert 'encrypted_blob' not in entries[0] and 'iv' not in entries[0]
    assert fake_key not in str(entries)
    assert checks == [('stripe', {'api_key': fake_key})]
    with factory() as db:
        row = db.query(CredentialWalletEntry).one()
        assert fake_key not in row.encrypted_blob
        assert {'wallet.created','wallet.verified'} <= {a.action for a in db.query(AuditLog).all()}
    assert client.post(path, headers=admin, json={'provider':'stripe','credentials':{'api_key':'pk_test_wrong'}}).status_code == 422
    invited = client.post('/org/users/invite', headers=admin, json={'email':'dev@example.com','full_name':'Dev','role':'developer','temporary_password':'dev password'}).json()['user_id']
    dev = login('dev@example.com','dev password')
    client.post('/auth/change-password', headers=dev, json={'current_password':'dev password','new_password':'new dev password'})
    assert client.post(f'/projects/{project}/members', headers=admin, json={'user_id':invited}).status_code == 201
    assert client.get(path, headers=dev).status_code == 403
    entry_id = entries[0]['id']
    assert client.post(f'{path}/{entry_id}/verify', headers=admin).status_code == 202
    assert client.delete(f'{path}/{entry_id}', headers=admin).status_code == 200
    assert client.get(path, headers=admin).json() == []


def test_verification_does_not_overwrite_newer_credentials(wallet_client, monkeypatch):
    client, factory, _ = wallet_client
    import wallet_verify
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com',
                'admin_password':'admin password','admin_full_name':'Admin'})
    token = client.post('/auth/token', data={'username':'admin@example.com','password':'admin password'}).json()['access_token']
    headers = {'Authorization':'Bearer ' + token}
    project = client.post('/projects', headers=headers, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    path = f'/projects/{project}/wallet'
    client.post(path, headers=headers, json={'provider':'stripe','credentials':{'api_key':'rk_test_12345'}})
    with factory() as db:
        row = db.query(CredentialWalletEntry).one()
        entry_id, old_iv = row.id, row.iv
    client.post(path, headers=headers, json={'provider':'stripe','credentials':{'api_key':'rk_test_67890'}})
    monkeypatch.setattr(wallet_verify, '_check', lambda *_: (_ for _ in ()).throw(PermissionError()))
    wallet_verify.verify_entry(entry_id, old_iv)
    assert client.get(path, headers=headers).json()[0]['verification_status'] == 'ok'


def test_stripe_verifier_uses_events_read_and_sanitizes_provider_errors(monkeypatch):
    import requests
    import wallet_verify
    calls = []
    class Response:
        status_code = 200
    class Session:
        trust_env = True
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(requests, 'Session', Session)
    wallet_verify._check('stripe', {'api_key':'rk_test_fake123'})
    assert calls[0][0] == 'https://api.stripe.com/v1/events'
    assert calls[0][1]['params'] == {'limit': 1}
    assert calls[0][1]['allow_redirects'] is False
    Response.status_code = 403
    with pytest.raises(PermissionError):
        wallet_verify._check('stripe', {'api_key':'rk_test_fake123'})


def test_wallet_accepts_twilio_auth_methods_and_validates_identifiers():
    from fastapi import HTTPException
    from routers.wallet import validate_credentials

    account = 'AC' + '1' * 32
    api_key = 'SK' + '2' * 32
    assert validate_credentials('twilio', {'account_sid': account, 'auth_token': 'token'})['account_sid'] == account
    values = {'account_sid': account, 'api_key_sid': api_key, 'api_key_secret': 'secret'}
    assert validate_credentials('twilio', values) == values
    assert validate_credentials('stripe', {'api_key': 'sk_test_fake123'})['api_key'] == 'sk_test_fake123'
    for invalid in ({**values, 'api_key_sid': 'ZS' + '2' * 32}, {**values, 'auth_token': 'token'},
                    {'account_sid': 'ZE' + '1' * 32, 'auth_token': 'token'}):
        with pytest.raises(HTTPException):
            validate_credentials('twilio', invalid)


def test_twilio_verification_uses_messages_and_selected_authentication(monkeypatch):
    import requests
    import wallet_verify
    calls = []
    class Response:
        status_code = 200
    class Session:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(requests, 'Session', Session)
    account, key = 'AC' + '1' * 32, 'SK' + '2' * 32
    wallet_verify._check('twilio', {'account_sid': account, 'api_key_sid': key, 'api_key_secret': 'secret'})
    wallet_verify._check('twilio', {'account_sid': account, 'auth_token': 'token'})
    assert calls[0][0].endswith(f'/Accounts/{account}/Messages.json')
    assert calls[0][1]['auth'] == (key, 'secret')
    assert calls[1][1]['auth'] == (account, 'token')
    assert all(call[1]['allow_redirects'] is False for call in calls)


def test_azure_verification_reads_activity_log_with_supplied_subscription(monkeypatch):
    import azure.identity
    import azure.mgmt.monitor
    import wallet_verify
    calls = []
    class Auth:
        def __init__(self, *args):
            calls.append(('auth', args))
        def close(self):
            pass
    class ActivityLogs:
        def list(self, **kwargs):
            calls.append(('list', kwargs))
            return iter([])
    class Client:
        def __init__(self, auth, subscription_id):
            calls.append(('subscription', subscription_id))
            self.activity_logs = ActivityLogs()
        def close(self):
            pass
    monkeypatch.setattr(azure.identity, 'ClientSecretCredential', Auth)
    monkeypatch.setattr(azure.mgmt.monitor, 'MonitorManagementClient', Client)
    wallet_verify._check('azure', {'tenant_id': 'tenant', 'client_id': 'app', 'client_secret': 'secret', 'subscription_id': 'sub'})
    assert ('subscription', 'sub') in calls
    assert calls[-1][0] == 'list'
    assert 'eventTimestamp ge' in calls[-1][1]['filter']
