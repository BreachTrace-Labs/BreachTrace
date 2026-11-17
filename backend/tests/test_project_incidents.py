"""Project-scoped incident and webhook isolation checks."""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient
from db.database import get_db
from db.models import IncidentRecord, Project


@pytest.fixture
def client_factory(sqlite_factory, monkeypatch):
    monkeypatch.setenv('JWT_SECRET_KEY', 'x' * 64)
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    monkeypatch.setenv('BREACHTRACE_LOCAL_TEST_MODE', 'true')
    from routers import simulate, webhook
    monkeypatch.setattr(simulate, 'index_incident_in_background', lambda *_: None)
    monkeypatch.setattr(webhook, 'index_incident_in_background', lambda *_: None)
    from main import app
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[get_db] = database
    yield TestClient(app), sqlite_factory
    app.dependency_overrides.clear()


def test_simulated_and_signed_webhook_incidents_are_scoped(client_factory, monkeypatch):
    client, factory = client_factory
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    def login(email, password):
        return {'Authorization':'Bearer ' + client.post('/auth/token', data={'username':email,'password':password}).json()['access_token']}
    admin = login('admin@example.com', 'admin password')
    def project(name):
        return client.post('/projects', headers=admin, json={'name':name,'github_repo_url':'https://github.com/acme/'+name}).json()['id']
    a, b = project('alpha'), project('beta')
    secret_a, secret_b = 'alpha-secret-value-123456', 'beta-secret-value-1234567'
    for project_id, secret in ((a, secret_a), (b, secret_b)):
        assert client.put(f'/webhook/projects/{project_id}/secret', headers=admin, json={'secret':secret}).status_code == 200
    with factory() as db:
        assert secret_a not in db.get(Project, a).webhook_secret
    diff = '+GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n'
    simulation = client.post('/test/simulate', headers=admin, json={'project_id':b,'diff_text':diff})
    assert simulation.status_code == 202, simulation.text
    b_incident = simulation.json()['incident_id']
    from routers import webhook
    monkeypatch.setattr(webhook, '_fetch_diff', lambda *_: diff)
    payload = {'repository':{'full_name':'acme/alpha'}, 'commits':[{'id':'a'*40,'timestamp':'2026-01-01T00:00:00Z'}]}
    body = json.dumps(payload).encode()
    def send(secret):
        signature = 'sha256=' + hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
        return client.post('/webhook/github',content=body,headers={'X-GitHub-Event':'push','X-Hub-Signature-256':signature})
    assert send(secret_b).status_code == 401
    response = send(secret_a)
    assert response.status_code == 202 and response.json()['incidents_created'] == 1
    a_incident = response.json()['incident_ids'][0]
    with factory() as db:
        assert db.get(IncidentRecord, a_incident).project_id == a
        assert db.get(IncidentRecord, b_incident).project_id == b
    unknown = client.post('/webhook/github',json={'repository':{'full_name':'acme/unknown'}},headers={'X-GitHub-Event':'push'})
    assert unknown.status_code == 200 and unknown.json()['status'] == 'ignored'
    invited = client.post('/org/users/invite',headers=admin,json={'email':'dev@example.com','full_name':'Dev','role':'developer','temporary_password':'dev password'}).json()['user_id']
    dev = login('dev@example.com','dev password')
    client.post('/auth/change-password',headers=dev,json={'current_password':'dev password','new_password':'new dev password'})
    client.post(f'/projects/{a}/members',headers=admin,json={'user_id':invited})
    result = client.get('/incidents',headers=dev)
    assert result.status_code == 200 and [item['incident_id'] for item in result.json()] == [a_incident]
    assert client.get(f'/incidents/{a_incident}',headers=dev).status_code == 200
    for suffix in ('', '/timeline', '/report.pdf'):
        assert client.get(f'/incidents/{b_incident}{suffix}',headers=dev).status_code == 403
    assert client.get('/incidents',headers=dev,params={'project_id':b}).status_code == 403
    assert client.post(f'/incidents/{b_incident}/refresh',headers=dev).status_code == 403
    assert client.post('/assistant/search',headers=dev,json={'question':'show incidents'}).status_code == 403
    assert len(client.get('/incidents',headers=admin).json()) == 2


def test_register_webhook_reuses_encrypted_secret_and_updates_existing_hook(client_factory, monkeypatch):
    client, factory = client_factory
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    admin = {'Authorization':'Bearer ' + client.post('/auth/token',data={'username':'admin@example.com','password':'admin password'}).json()['access_token']}
    project_id = client.post('/projects',headers=admin,json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    calls=[]
    class Hook:
        id = 123
        config = {'url':'https://example.test/webhook/github'}
        def edit(self, **kwargs): calls.append(kwargs)
    class Repo:
        def get_hooks(self): return [Hook()]
        def create_hook(self, **kwargs): raise AssertionError('Existing webhook must be updated')
    class Github:
        def __init__(self, *_): pass
        def get_repo(self, name):
            assert name == 'acme/app'
            return Repo()
    from routers import webhook
    monkeypatch.setattr(webhook, 'Github', Github)
    request = {'project_id':project_id,'webhook_url':'https://example.test/webhook/github'}
    assert client.post('/webhook/register',headers=admin,json=request).status_code == 200
    assert client.post('/webhook/register',headers=admin,json=request).status_code == 200
    assert calls[0]['config']['secret'] == calls[1]['config']['secret']
    with factory() as db:
        project = db.get(Project, project_id)
        assert project.webhook_registered_at is not None
        assert calls[0]['config']['secret'] not in project.webhook_secret


def test_admin_can_associate_only_matching_unassigned_incidents(client_factory):
    client, factory = client_factory
    from datetime import datetime, timezone
    client.post('/auth/register',json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    admin = {'Authorization':'Bearer ' + client.post('/auth/token',data={'username':'admin@example.com','password':'admin password'}).json()['access_token']}
    project_id = client.post('/projects',headers=admin,json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    from db.crud import create_incident
    with factory() as db:
        for repo in ('https://github.com/acme/app', 'https://github.com/acme/other'):
            create_incident(db,credential_type='github_pat',credential_hint='ghp_****test',repo_url=repo,commit_hash='a'*40,exposure_start=datetime.now(timezone.utc))
    response = client.post(f'/projects/{project_id}/adopt-legacy',headers=admin)
    assert response.status_code == 200 and response.json()['adopted'] == 1
    assert len(client.get('/incidents',headers=admin).json()) == 1
    with factory() as db:
        assert db.query(IncidentRecord).filter(IncidentRecord.project_id.is_(None)).count() == 1


def test_azure_secret_requires_authorized_explicit_application_association(client_factory, monkeypatch):
    from datetime import datetime, timezone
    import config
    from db.crud import create_incident
    from routers import incidents
    from routers.settings import local_operator
    from main import app

    client, factory = client_factory
    app.dependency_overrides[local_operator] = lambda: None
    for name in ('AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID'):
        monkeypatch.setattr(config, name, 'configured')
    runs = []
    monkeypatch.setattr(incidents, 'run_collection_pipeline', lambda *args, **kwargs: runs.append((args, kwargs)))
    client.post('/auth/register', json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com',
                                       'admin_password':'admin password','admin_full_name':'Admin'})
    token = client.post('/auth/token', data={'username':'admin@example.com','password':'admin password'}).json()['access_token']
    headers = {'Authorization':'Bearer ' + token}
    project = client.post('/projects', headers=headers, json={'name':'App','github_repo_url':'https://github.com/acme/app'}).json()['id']
    with factory() as db:
        incident = create_incident(db, credential_type='azure_client_secret', credential_hint='masked',
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40, exposure_start=datetime.now(timezone.utc),
                                   forensic_tier=2, project_id=project)
        incident_id = incident.incident_id
    path = f'/incidents/{incident_id}/azure-application'
    client_id = '11111111-2222-3333-4444-555555555555'
    assert client.post(path, json={'client_id':client_id}).status_code == 401
    assert client.post(path, headers=headers, json={'client_id':'invalid'}).status_code == 422
    assert client.post(path, headers=headers, json={'client_id':client_id}).status_code == 202
    with factory() as db:
        updated = db.get(IncidentRecord, incident_id)
        assert updated.principal_id == client_id and updated.forensic_tier == 1
        assert updated.status == 'collecting'
    assert len(runs) == 1 and runs[0][0][1] == client_id and runs[0][1]['platform'] == 'azure'
    assert client.post(path, headers=headers, json={'client_id':client_id}).status_code == 400
