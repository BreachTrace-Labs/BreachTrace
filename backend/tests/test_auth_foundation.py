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
