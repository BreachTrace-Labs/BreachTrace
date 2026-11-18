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
    assert client.get(path, headers=dev).status_code == 200
    entry_id = entries[0]['id']
    assert client.post(f'{path}/{entry_id}/verify', headers=dev).status_code == 403
    assert client.delete(f'{path}/{entry_id}', headers=dev).status_code == 403
    assert client.post(f'{path}/{entry_id}/verify', headers=admin).status_code == 202
    assert client.delete(f'{path}/{entry_id}', headers=admin).status_code == 200
    assert client.get(path, headers=admin).json() == []


def test_gcp_impersonation_source_is_write_only_and_used_for_verification(wallet_client):
    import json
    import wallet_verify
    from crypto import decrypt_blob
    client, factory, checks = wallet_client
    assert client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com',
                       'admin_password':'admin password','admin_full_name':'Admin'}).status_code == 201
    token = client.post('/auth/token', data={'username':'admin@example.com','password':'admin password'}).json()['access_token']
    headers = {'Authorization':'Bearer ' + token}
    project = client.post('/projects', headers=headers, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    source = json.dumps({'type':'service_account', 'project_id':'source-project', 'private_key':'sensitive-test-value',
                         'client_email':'source@source-project.iam.gserviceaccount.com',
                         'token_uri':'https://oauth2.googleapis.com/token'})
    values = {'auth_mode':'impersonation', 'project_id':'example-project',
              'reader_service_account':'reader@example-project.iam.gserviceaccount.com', 'source_service_account_json':source}
    path = f'/projects/{project}/wallet'
    response = client.post(path, headers=headers, json={'provider':'gcp', 'credentials':values})
    assert response.status_code == 202
    assert 'sensitive-test-value' not in response.text and 'sensitive-test-value' not in client.get(path, headers=headers).text
    with factory() as db:
        entry = db.query(CredentialWalletEntry).one()
        assert 'sensitive-test-value' not in entry.encrypted_blob
        assert decrypt_blob(entry.encrypted_blob, entry.iv) == values
        entry_id, iv = entry.id, entry.iv
    assert wallet_verify.verify_entry(entry_id, iv)
    assert checks == [('gcp', values)]
    assert client.get(path, headers=headers).json()[0]['verification_status'] == 'ok'


@pytest.mark.parametrize('exception_name,expected', [
    ('DefaultCredentialsError', 'Application Default Credentials are unavailable'),
    ('Forbidden', 'denied impersonation or log access'),
    ('RefreshError', 'authentication failed'),
    ('DeadlineExceeded', 'timed out'),
])
def test_gcp_verification_errors_are_actionable_and_redacted(sqlite_factory, monkeypatch, exception_name, expected):
    import wallet_verify
    from crypto import encrypt_blob
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    monkeypatch.setattr(wallet_verify, 'SessionLocal', sqlite_factory)
    ciphertext, iv = encrypt_blob({'auth_mode':'impersonation', 'project_id':'demo-project',
                                   'reader_service_account':'reader@demo-project.iam.gserviceaccount.com'})
    with sqlite_factory() as db:
        entry = CredentialWalletEntry(project_id='project-a', provider='gcp', encrypted_blob=ciphertext,
                                      iv=iv, created_by='admin', verification_status='pending')
        db.add(entry)
        db.commit()
        entry_id = entry.id
    exception = type(exception_name, (Exception,), {})
    def fail(*_):
        raise exception('sensitive provider details')
    monkeypatch.setattr(wallet_verify, '_check', fail)
    assert not wallet_verify.verify_entry(entry_id, iv)
    with sqlite_factory() as db:
        entry = db.get(CredentialWalletEntry, entry_id)
        assert entry.verification_status == 'error'
        assert expected in entry.verification_error
        assert 'sensitive provider details' not in entry.verification_error


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


def test_developer_can_add_but_not_replace_project_reader(wallet_client):
    client, factory, _ = wallet_client
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com',
                'admin_password':'admin password','admin_full_name':'Admin'})
    def login(email, password):
        return {'Authorization': 'Bearer ' + client.post('/auth/token', data={'username':email, 'password':password}).json()['access_token']}
    admin = login('admin@example.com', 'admin password')
    a = client.post('/projects', headers=admin, json={'name':'Assigned','github_repo_url':'https://github.com/acme/assigned'}).json()['id']
    b = client.post('/projects', headers=admin, json={'name':'Other','github_repo_url':'https://github.com/acme/other'}).json()['id']
    dev_id = client.post('/org/users/invite', headers=admin, json={'email':'dev@example.com','full_name':'Dev',
        'role':'developer','temporary_password':'temporary password'}).json()['user_id']
    dev = login('dev@example.com', 'temporary password')
    assert client.post('/auth/change-password', headers=dev, json={'current_password':'temporary password','new_password':'new password 123'}).status_code == 200
    client.post(f'/projects/{a}/members', headers=admin, json={'user_id':dev_id})
    path = f'/projects/{a}/wallet'
    payload = {'provider':'stripe','label':'Reader','credentials':{'api_key':'rk_test_fakeReaderForTest'}}
    assert client.get(f'/projects/{b}/wallet', headers=dev).status_code == 403
    assert client.post(f'/projects/{b}/wallet', headers=dev, json=payload).status_code == 403
    response = client.post(path, headers=dev, json=payload)
    assert response.status_code == 202 and payload['credentials']['api_key'] not in response.text
    entry_id = response.json()['id']
    entries = client.get(path, headers=dev).json()
    assert len(entries) == 1 and 'credentials' not in entries[0] and payload['credentials']['api_key'] not in str(entries)
    assert client.post(path, headers=dev, json=payload).status_code == 409
    assert client.post(f'{path}/{entry_id}/verify', headers=dev).status_code == 403
    assert client.delete(f'{path}/{entry_id}', headers=dev).status_code == 403
    with factory() as db:
        row = db.get(CredentialWalletEntry, entry_id)
        assert row.created_by == dev_id and payload['credentials']['api_key'] not in row.encrypted_blob
        assert any(entry.action == 'wallet.created' and entry.actor_user_id == dev_id for entry in db.query(AuditLog).all())
    client.post(f'/projects/{b}/members', headers=admin, json={'user_id':dev_id})
    assert {project['id'] for project in client.get('/projects', headers=dev).json()} == {a, b}
    assert client.get(f'/projects/{b}/wallet', headers=dev).json() == []
    client.delete(f'/projects/{a}/members/{dev_id}', headers=admin)
    assert client.get(path, headers=dev).status_code == 403
