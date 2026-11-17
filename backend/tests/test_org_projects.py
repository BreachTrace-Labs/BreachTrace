"""Exercise organisation boundaries, membership, and API entrypoint protection."""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from db.database import get_db
from db.models import AuditLog, Organisation, User
from auth import hash_password


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


def test_membership_org_boundary_and_role_changes(app_client):
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
        other = Organisation(name='Other', slug='other')
        db.add(other); db.flush()
        outside = User(organisation_id=other.id,email='outside@example.com',full_name='Outside',role='security_lead',hashed_password=hash_password('outside password'))
        db.add(outside); db.commit(); outside_id = outside.id
    outside = login(client, 'outside@example.com', 'outside password')
    assert client.get(f'/projects/{project_id}', headers=outside).status_code == 404
    assert client.post(f'/projects/{project_id}/members', headers=admin, json={'user_id':outside_id}).status_code == 404
    assert client.put(f'/org/users/{dev_id}', headers=admin, json={'role':'security_lead'}).status_code == 200
    assert client.get('/incidents', headers=dev).status_code == 200
    assert client.delete(f'/org/users/{dev_id}', headers=admin).status_code == 200
    assert client.get('/projects', headers=dev).status_code == 401
    with factory() as db:
        assert {'user.invited','user.role_changed','user.deactivated','project.created','project.member_added'} <= {row.action for row in db.query(AuditLog).all()}


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
