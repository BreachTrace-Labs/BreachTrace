"""Security boundaries for login, origins, and incident evidence."""
from fastapi.testclient import TestClient


def test_login_rate_limit_is_per_client_ip(sqlite_factory, monkeypatch):
    from db.database import get_db
    monkeypatch.setenv("BREACHTRACE_LOCAL_TEST_MODE", "true")
    from main import app

    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[get_db] = database
    try:
        first = TestClient(app, client=("192.0.2.10", 1234))
        second = TestClient(app, client=("192.0.2.11", 1234))
        credentials = {"username": "nobody@example.com", "password": "wrong"}
        assert [first.post('/auth/token', data=credentials).status_code for _ in range(5)] == [401] * 5
        response = first.post('/auth/token', data=credentials)
        assert response.status_code == 429
        assert second.post('/auth/token', data=credentials).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_cors_accepts_configured_local_frontend_only(monkeypatch):
    monkeypatch.setenv("BREACHTRACE_LOCAL_TEST_MODE", "true")
    from main import app
    client = TestClient(app)
    allowed = client.options('/auth/token', headers={'Origin': 'http://127.0.0.1:5173', 'Access-Control-Request-Method': 'POST'})
    rejected = client.options('/auth/token', headers={'Origin': 'https://untrusted.example', 'Access-Control-Request-Method': 'POST'})
    assert allowed.status_code == 200
    assert allowed.headers['access-control-allow-origin'] == 'http://127.0.0.1:5173'
    assert rejected.status_code == 400
    assert 'access-control-allow-origin' not in rejected.headers


def test_raw_provider_evidence_and_credential_ids_are_masked():
    from datetime import datetime, timezone
    from routers.incidents import ForensicEventOut, IncidentSummaryOut

    secret = 'sk_test_' + 'a' * 32
    key_id = 'AKIA' + 'A' * 16
    event = ForensicEventOut(event_id='event', platform='aws', timestamp=datetime.now(timezone.utc),
        api_action='GetObject', event_source=None, source_ip=None, user_agent=None,
        affected_resource=None, resource_type=None, success=True, error_code=None,
        is_denied=False, impact_category=None, severity_weight=None,
        raw_data={'nested': {'api_key': secret}, 'message': f'key {secret}', 'region': 'us-east-1'})
    assert secret not in event.model_dump_json()
    assert event.raw_data['nested']['api_key'] == '[REDACTED]'
    assert event.raw_data['region'] == 'us-east-1'
    incident = IncidentSummaryOut(incident_id='id', credential_type='aws_access_key',
        credential_hint='AKIA****AAAA', access_key_id=key_id, repo_url='https://github.com/a/b',
        commit_hash=None, exposure_start=datetime.now(timezone.utc), exposure_end=None,
        status='complete', overall_severity=None, gdpr_flag=False, created_at=datetime.now(timezone.utc))
    assert key_id not in incident.model_dump_json()
    assert incident.access_key_id == 'AKIA****AAAA'
