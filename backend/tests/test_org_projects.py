"""Exercise organisation boundaries, membership, and API entrypoint protection."""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from db.database import get_db
from db.models import AuditLog, Organisation


@pytest.fixture
def app_client(sqlite_factory, monkeypatch):
    monkeypatch.setenv('JWT_SECRET_KEY', 'x' * 64)
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    monkeypatch.setenv('BREACHTRACE_LOCAL_TEST_MODE', 'true')
    monkeypatch.setenv('STRIPE_LOG_INGEST_TOKEN', 'stream-token')
    import config
    monkeypatch.setattr(config, 'GITHUB_WEBHOOK_SECRET', 'webhook-test-secret')
    from main import app
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[get_db] = database
    yield TestClient(app), sqlite_factory
    app.dependency_overrides.clear()


def login(client, email, password):
    response = client.post('/auth/token', data={'username': email, 'password': password})
    assert response.status_code == 200
    return {'Authorization': 'Bearer ' + response.json()['access_token']}


def test_membership_single_organisation_and_role_changes(app_client):
    client, factory = app_client
    assert client.get('/incidents').status_code == 401
    assert client.get('/webhook/info').status_code == 401
    assert client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com',
           'admin_password':'admin password','admin_full_name':'Admin'}).status_code == 201
    admin = login(client, 'admin@example.com', 'admin password')
    created = client.post('/projects', headers=admin, json={'name':'App','github_repo_url':'https://github.com/Acme/App.git'})
    assert created.status_code == 201, created.text
    project_id = created.json()['id']
    invite = client.post('/org/users/invite', headers=admin, json={'email':'dev@example.com', 'full_name':'Developer',
                         'role':'developer', 'temporary_password':'developer password'})
    assert invite.status_code == 201
    dev_id = invite.json()['user_id']
    dev = login(client, 'dev@example.com', 'developer password')
    assert client.get('/projects', headers=dev).status_code == 403
    assert client.post('/auth/change-password', headers=dev, json={'current_password':'developer password', 'new_password':'new developer password'}).status_code == 200
    assert client.get('/projects', headers=dev).json() == []
    assert client.get(f'/projects/{project_id}', headers=dev).status_code == 403
    assert client.get('/incidents', headers=dev).json() == []
    assert client.post(f'/projects/{project_id}/members', headers=admin, json={'user_id':dev_id}).status_code == 201
    assert client.get(f'/projects/{project_id}', headers=dev).status_code == 200
    assert len(client.get('/projects', headers=dev).json()) == 1
    with factory() as db:
        db.add(Organisation(name='Other', slug='other'))
        with pytest.raises(IntegrityError):
            db.commit()
    assert client.put(f'/org/users/{dev_id}', headers=admin, json={'role':'security_lead'}).status_code == 200
    assert client.get('/incidents', headers=dev).status_code == 200
    assert client.delete(f'/org/users/{dev_id}', headers=admin).status_code == 200
    assert client.get('/projects', headers=dev).status_code == 401
    with factory() as db:
        assert {'user.invited','user.role_changed','user.deactivated','project.created','project.member_added'} <= {row.action for row in db.query(AuditLog).all()}


def test_organisation_wide_features_are_restricted_to_admins_and_leads(app_client):
    from main import app
    from routers.settings import local_operator
    client, _ = app_client
    app.dependency_overrides[local_operator] = lambda: None
    body = {'org_name':'Acme', 'slug':'acme', 'admin_email':'admin@example.com',
            'admin_password':'admin password', 'admin_full_name':'Admin'}
    assert client.post('/auth/register', json=body).status_code == 201
    assert client.post('/auth/register', json=body).status_code == 409
    admin = login(client, 'admin@example.com', 'admin password')
    for role, email in [('developer', 'dev@example.com'), ('security_lead', 'lead@example.com')]:
        assert client.post('/org/users/invite', headers=admin, json={'email':email, 'full_name':role,
                           'role':role, 'temporary_password':'temporary password'}).status_code == 201
        user = login(client, email, 'temporary password')
        assert client.post('/auth/change-password', headers=user, json={'current_password':'temporary password',
                           'new_password':'new password'}).status_code == 200
        expected = 403 if role == 'developer' else 200
        assert client.get('/research/platforms', headers=user).status_code == expected
        assert client.get('/assistant/status', headers=user).status_code == expected
        expected_scan = 403 if role == 'developer' else 404
        assert client.get('/repositories/scans/00000000-0000-0000-0000-000000000000', headers=user).status_code == expected_scan


def test_webhook_is_hmac_protected_and_stream_keeps_its_own_auth(app_client):
    client, _ = app_client
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    admin = login(client, 'admin@example.com', 'admin password')
    project_id = client.post('/projects', headers=admin, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    secret = 'webhook-test-secret-123'
    assert client.put(f'/webhook/projects/{project_id}/secret', headers=admin, json={'secret':secret}).status_code == 200
    body = json.dumps({'repository':{'full_name':'acme/app'},'zen':'hello'}).encode()
    signature = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert client.post('/webhook/github', content=body, headers={'X-GitHub-Event':'ping'}).status_code == 401
    response = client.post('/webhook/github', content=body, headers={'X-GitHub-Event':'ping', 'X-Hub-Signature-256':signature})
    assert response.status_code == 202
    from routers import incidents
    if not hasattr(incidents, 'stream_router'):
        return  # Optional local Stripe streaming changes may not be installed.
    path = '/incidents/not-an-incident/stripe-request-logs'
    assert client.post(path, json={}).status_code == 403
    assert client.post(path, headers={'Authorization':'Bearer stream-token'}, json={}).status_code == 422


def test_legacy_database_with_multiple_organisations_fails_closed(app_client):
    client, factory = app_client
    client.post('/auth/register', json={'org_name':'Acme', 'slug':'acme', 'admin_email':'admin@example.com',
                                       'admin_password':'admin password', 'admin_full_name':'Admin'})
    admin = login(client, 'admin@example.com', 'admin password')
    project = client.post('/projects', headers=admin, json={'name':'App', 'github_repo_url':'https://github.com/acme/app'}).json()['id']
    secret = 'webhook-test-secret-123'
    assert client.put(f'/webhook/projects/{project}/secret', headers=admin, json={'secret':secret}).status_code == 200
    with factory() as db:
        db.execute(text('DROP INDEX uq_organisation_singleton'))
        db.add(Organisation(name='Other', slug='other'))
        db.commit()
    assert client.get('/research/platforms', headers=admin).status_code == 503
    assert client.get('/projects', headers=admin).status_code == 503
    assert client.post('/auth/token', data={'username':'admin@example.com', 'password':'admin password'}).status_code == 503
    body = json.dumps({'repository':{'full_name':'acme/app'}, 'zen':'hello'}).encode()
    signature = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert client.post('/webhook/github', content=body, headers={'X-GitHub-Event':'ping',
                       'X-Hub-Signature-256':signature}).status_code == 503


def test_github_invitation_requires_configuration_and_verified_email(app_client, monkeypatch):
    from db.models import BackgroundJob, User
    from github_oauth import GitHubIdentity
    import notifications

    client, factory = app_client
    client.post('/auth/register', json={'org_name': 'Acme', 'slug': 'acme', 'admin_email': 'admin@example.com',
                                       'admin_password': 'admin password', 'admin_full_name': 'Admin'})
    admin = login(client, 'admin@example.com', 'admin password')
    invitation = {'email': 'dev@example.com', 'full_name': 'Developer', 'role': 'developer', 'sign_in_method': 'github'}
    monkeypatch.delenv('GITHUB_OAUTH_CLIENT_ID', raising=False)
    assert client.post('/org/users/invite', headers=admin, json=invitation).status_code == 503
    monkeypatch.setenv('GITHUB_OAUTH_CLIENT_ID', 'client')
    monkeypatch.setenv('GITHUB_OAUTH_CLIENT_SECRET', 'secret')
    monkeypatch.setenv('GITHUB_OAUTH_CALLBACK_URL', 'http://127.0.0.1:5173/auth/github/callback')
    assert client.post('/org/users/invite', json=invitation).status_code == 401
    response = client.post('/org/users/invite', headers=admin, json=invitation)
    assert response.status_code == 201, response.text
    assert client.post('/org/users/invite', headers=admin, json=invitation).status_code == 409
    with factory() as db:
        user = db.get(User, response.json()['user_id'])
        assert user.hashed_password is None and not user.must_change_password
        payload = db.query(BackgroundJob).filter_by(kind='notification').one().payload
        assert payload['method'] == 'github' and 'ciphertext' not in payload
    sent = []
    monkeypatch.setattr(notifications, 'SessionLocal', factory)
    monkeypatch.setattr(notifications, 'send_email', lambda *args: sent.append(args) or True)
    assert notifications.deliver_job(payload) == 'sent'
    assert 'Continue with GitHub' in sent[0][3] and 'verified' in sent[0][3]
    assert 'Temporary password' not in sent[0][3]
    assert client.post('/auth/token', data={'username': 'dev@example.com', 'password': 'any password'}).status_code == 401
    async def unverified(*args, **kwargs):
        return GitHubIdentity('42', 'person', ())
    monkeypatch.setattr('routers.auth.fetch_identity', unverified)
    exchange = {'code': 'code', 'code_verifier': 'a' * 43}
    assert client.post('/auth/github/exchange', json=exchange).status_code == 403
    async def verified(*args, **kwargs):
        return GitHubIdentity('42', 'person', ('dev@example.com',))
    monkeypatch.setattr('routers.auth.fetch_identity', verified)
    result = client.post('/auth/github/exchange', json=exchange)
    assert result.status_code == 200
    assert result.json()['user']['role'] == 'developer'
    assert result.json()['user']['must_change_password'] is False
    assert result.json()['user']['has_password'] is False
    assert notifications.deliver_job(payload) == 'skipped'
    assert client.delete('/org/users/' + response.json()['user_id'], headers=admin).status_code == 200
    assert client.post('/auth/github/exchange', json=exchange).status_code == 403


def test_exposure_observations_are_attributed_and_do_not_close_window(app_client):
    from datetime import datetime, timezone, timedelta
    from db.crud import create_incident
    from db.models import IncidentRecord
    client, factory = app_client
    client.post('/auth/register', json={'org_name':'Acme', 'slug':'acme', 'admin_email':'admin@example.com',
                                      'admin_password':'admin password', 'admin_full_name':'Admin'})
    admin = login(client, 'admin@example.com', 'admin password')
    project = client.post('/projects', headers=admin, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    with factory() as db:
        incident = create_incident(db, credential_type='aws_access_key', credential_hint='AKIA****TEST',
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40,
                                   exposure_start=datetime.now(timezone.utc) - timedelta(days=1), project_id=project)
        incident_id = incident.incident_id
    path = f'/incidents/{incident_id}/exposure-observations'
    body = {'kind':'revoked', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'source':'Provider audit record 123', 'confidence':'high'}
    assert client.post(path, json=body).status_code == 401
    assert client.post(path, headers=admin, json={**body, 'observed_at':'2025-01-01T12:00:00'}).status_code == 422
    assert client.post(path, headers=admin, json={**body, 'observed_at':(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}).status_code == 422
    result = client.post(path, headers=admin, json=body)
    assert result.status_code == 201, result.text
    assert result.json()['verification'] == 'operator_reported'
    assert result.json()['recorded_by'] == 'Admin' and result.json()['credential_hint'] == 'AKIA****TEST'
    assert len(client.get(path, headers=admin).json()) == 1
    with factory() as db:
        assert db.get(IncidentRecord, incident_id).exposure_end is None
    user_id = client.post('/org/users/invite', headers=admin, json={'email':'dev@example.com', 'full_name':'Dev',
                          'role':'developer', 'temporary_password':'developer password'}).json()['user_id']
    dev = login(client, 'dev@example.com', 'developer password')
    client.post('/auth/change-password', headers=dev, json={'current_password':'developer password', 'new_password':'new developer password'})
    assert client.get(path, headers=dev).status_code == 403
    client.post(f'/projects/{project}/members', headers=admin, json={'user_id':user_id})
    assert client.get(path, headers=dev).status_code == 200
    assert client.post(path, headers=dev, json=body).status_code == 403


def test_gcp_key_association_labels_events_without_changing_them(app_client):
    from datetime import datetime, timezone
    from db.crud import create_incident, save_forensic_events
    from db.models import GCPKeyAssociation
    from normalizer.schema import ForensicEvent
    client, factory = app_client
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    admin = login(client, 'admin@example.com', 'admin password')
    project = client.post('/projects', headers=admin, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    email = 'svc@demo.iam.gserviceaccount.com'
    key = 'a' * 40
    with factory() as db:
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='svc...', principal_id=email,
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40,
                                   exposure_start=datetime.now(timezone.utc), project_id=project)
        incident_id = incident.incident_id
        events = [ForensicEvent(platform='gcp', timestamp=datetime.now(timezone.utc), api_action='test', raw_data={'authenticationInfo': {'principalEmail':email, 'serviceAccountKeyName':f'//iam.googleapis.com/projects/demo/serviceAccounts/{email}/keys/{value}'}}) for value in (key, 'b' * 40)]
        save_forensic_events(db, incident_id, events)
    path = f'/incidents/{incident_id}/gcp-key-association'
    assert client.post(path, headers=admin, json={'key_id':key, 'confirms_incident_key':False}).status_code == 422
    result = client.post(path, headers=admin, json={'key_id':key, 'confirms_incident_key':True})
    assert result.status_code == 200 and key not in result.text
    detail = client.get(f'/incidents/{incident_id}', headers=admin)
    assert detail.status_code == 200, detail.text
    assert [e['gcp_key_attribution'] for e in detail.json()['events']] == ['matched', 'different_key']
    assert detail.json()['gcp_key_association']['verification'] == 'operator_reported'
    with factory() as db:
        assert db.get(GCPKeyAssociation, incident_id).key_digest != key


def test_azure_signins_require_authorized_project_and_verified_reader(app_client, monkeypatch):
    from datetime import datetime, timezone
    from crypto import encrypt_blob
    from db.crud import create_incident
    from db.models import CredentialWalletEntry
    import collectors.azure_signins as signins
    client, factory = app_client
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    admin = login(client, 'admin@example.com', 'admin password')
    project = client.post('/projects', headers=admin, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    app_id = '11111111-2222-3333-4444-555555555555'
    with factory() as db:
        incident = create_incident(db, credential_type='azure_client_secret', credential_hint='masked', principal_id=app_id,
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40,
                                   exposure_start=datetime.now(timezone.utc), project_id=project)
        incident_id = incident.incident_id
    path = f'/incidents/{incident_id}/azure-signins'
    assert client.post(path, json={}).status_code == 401
    assert client.post(path, headers=admin, json={}).status_code == 422
    values = {'tenant_id':'tenant', 'client_id':'reader', 'client_secret':'secret', 'subscription_id':'sub'}
    ciphertext, iv = encrypt_blob(values)
    with factory() as db:
        db.add(CredentialWalletEntry(project_id=project, provider='azure', encrypted_blob=ciphertext, iv=iv,
                                     created_by=client.get('/auth/me', headers=admin).json()['id'], verification_status='ok'))
        db.commit()
    calls = []
    monkeypatch.setattr(signins, 'collect_signins', lambda reader, application, key: calls.append((reader, application, key)) or {'events':[], 'truncated':False})
    result = client.post(path, headers=admin, json={})
    assert result.status_code == 200 and calls[0][0] == values and calls[0][1] == app_id
    user_id = client.post('/org/users/invite', headers=admin, json={'email':'dev@example.com','full_name':'Dev','role':'developer','temporary_password':'developer password'}).json()['user_id']
    dev = login(client, 'dev@example.com', 'developer password')
    client.post('/auth/change-password', headers=dev, json={'current_password':'developer password','new_password':'new developer password'})
    client.post(f'/projects/{project}/members', headers=admin, json={'user_id':user_id})
    assert client.post(path, headers=dev, json={}).status_code == 403
    assert len(calls) == 1
