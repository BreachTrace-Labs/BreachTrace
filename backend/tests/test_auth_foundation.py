"""Authentication and encryption foundation integration checks."""
import pytest
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI
from fastapi.testclient import TestClient

from db.database import get_db
from db.models import AuditLog
from routers.auth import router
from rate_limit import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded


@pytest.fixture
def client(sqlite_factory, monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(router)
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[get_db] = database
    with TestClient(app) as test_client:
        yield test_client, sqlite_factory


def test_setup_login_and_password_change(client):
    c, factory = client
    body = {"org_name": "Example", "slug": "example", "admin_email": "admin@example.com", "admin_password": "a secure password", "admin_full_name": "Example Admin"}
    assert c.get('/auth/setup-status').json()['setup_required'] is True
    assert c.post('/auth/register', json=body).status_code == 201
    assert c.post('/auth/register', json=body).status_code == 409
    assert c.post('/auth/token', data={'username': body['admin_email'], 'password': 'wrong'}).status_code == 401
    result = c.post('/auth/token', data={'username': body['admin_email'], 'password': body['admin_password']})
    assert result.status_code == 200
    headers = {'Authorization': 'Bearer ' + result.json()['access_token']}
    assert c.get('/auth/me', headers=headers).json()['role'] == 'org_admin'
    assert c.get('/auth/me', headers={'Authorization': 'Bearer invalid'}).status_code == 401
    assert c.put('/auth/me', json={'full_name': 'No access'}).status_code == 401
    assert c.put('/auth/me', headers=headers, json={'full_name': '   '}).status_code == 422
    assert c.put('/auth/me', headers=headers, json={'full_name': ' Updated Name '}).json()['full_name'] == 'Updated Name'
    assert c.get('/auth/me', headers=headers).json()['full_name'] == 'Updated Name'
    assert c.post('/auth/change-password', headers=headers, json={'current_password': body['admin_password'], 'new_password': 'another secure password'}).status_code == 200
    assert c.post('/auth/token', data={'username': body['admin_email'], 'password': body['admin_password']}).status_code == 401
    with factory() as db:
        assert {row.action for row in db.query(AuditLog).all()} >= {'auth.login', 'auth.password_changed'}


def test_wallet_encryption_integrity(monkeypatch):
    from crypto import decrypt_blob, encrypt_blob
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    ciphertext, nonce = encrypt_blob({'api_key': 'test-value'})
    assert 'test-value' not in ciphertext
    assert decrypt_blob(ciphertext, nonce) == {'api_key': 'test-value'}
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '34' * 32)
    with pytest.raises(InvalidTag):
        decrypt_blob(ciphertext, nonce)


def test_github_signin_requires_config_and_invited_verified_account(client, monkeypatch):
    from github_oauth import GitHubIdentity
    from db.models import User
    c, factory = client
    body = {'code': 'temporary-code', 'code_verifier': 'a' * 43}
    monkeypatch.delenv('GITHUB_OAUTH_CLIENT_ID', raising=False)
    assert c.post('/auth/github/exchange', json=body).status_code == 503
    monkeypatch.setenv('GITHUB_OAUTH_CLIENT_ID', 'client')
    monkeypatch.setenv('GITHUB_OAUTH_CLIENT_SECRET', 'secret')
    monkeypatch.setenv('GITHUB_OAUTH_CALLBACK_URL', 'http://127.0.0.1:5173/auth/github/callback')
    assert c.get('/auth/github/config').json() == {'enabled': True, 'client_id': 'client', 'callback_url': 'http://127.0.0.1:5173/auth/github/callback'}
    assert c.post('/auth/register', json={'org_name': 'Example', 'slug': 'example', 'admin_email': 'admin@example.com', 'admin_password': 'a secure password', 'admin_full_name': 'Example Admin'}).status_code == 201
    async def identity(*args, **kwargs):
        return GitHubIdentity('42', 'person', ('admin@example.com',))
    monkeypatch.setattr('routers.auth.fetch_identity', identity)
    result = c.post('/auth/github/exchange', json=body)
    assert result.status_code == 200
    assert result.json()['user']['role'] == 'org_admin'
    assert c.get('/auth/me', headers={'Authorization': 'Bearer ' + result.json()['access_token']}).status_code == 200
    with factory() as db:
        user = db.query(User).filter_by(email='admin@example.com').one()
        user.is_active = False
        db.commit()
        assert db.query(AuditLog).filter_by(action='auth.github_login').count() == 1
    assert c.post('/auth/github/exchange', json=body).status_code == 403
    async def uninvited(*args, **kwargs):
        return GitHubIdentity('42', 'person', ('other@example.com',))
    monkeypatch.setattr('routers.auth.fetch_identity', uninvited)
    assert c.post('/auth/github/exchange', json=body).status_code == 403
    assert c.post('/auth/github/exchange', json={'code': 'x', 'code_verifier': 'short'}).status_code == 422
    monkeypatch.setenv('GITHUB_OAUTH_CALLBACK_URL', 'http://example.com/auth/github/callback')
    assert c.get('/auth/github/config').json()['enabled'] is False
