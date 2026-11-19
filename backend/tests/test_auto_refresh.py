from datetime import datetime, timedelta, timezone
from uuid import uuid4

from crypto import encrypt_blob
from db.crud import create_incident
from db.models import BackgroundJob, CredentialWalletEntry, Organisation, Project, User


def test_recurring_schedule_queues_eligible_incidents_without_duplicate_jobs(sqlite_factory, monkeypatch):
    import auto_refresh
    import background_jobs
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    monkeypatch.setattr(auto_refresh, 'SessionLocal', sqlite_factory)
    monkeypatch.setattr(background_jobs, 'SessionLocal', sqlite_factory)
    org, actor, project = str(uuid4()), str(uuid4()), str(uuid4())
    now = datetime.now(timezone.utc)
    with sqlite_factory() as db:
        db.add(Organisation(id=org, name='Example', slug='example'))
        db.add(User(id=actor, organisation_id=org, email='admin@example.test', full_name='Admin', role='org_admin'))
        db.add(Project(id=project, organisation_id=org, name='App', created_by=actor,
                       github_repo_url='https://github.com/example/app', github_repo_full_name='example/app'))
        encrypted, iv = encrypt_blob({'access_key_id': 'reader', 'secret_access_key': 'unused', 'region': 'us-east-1'})
        db.add(CredentialWalletEntry(project_id=project, provider='aws', encrypted_blob=encrypted,
                                     iv=iv, created_by=actor, verification_status='ok'))
        db.add(BackgroundJob(kind='auto_refresh', dedupe_key=f'auto-refresh:{org}', status='queued',
                             payload={'organisation_id': org, 'enabled': True, 'interval_minutes': 60},
                             available_at=now - timedelta(minutes=1)))
        db.commit()
        incident = create_incident(db, credential_type='aws_access_key', credential_hint='masked',
                                   access_key_id='investigated', repo_url='https://github.com/example/app',
                                   commit_hash='a' * 40, exposure_start=now, project_id=project)
        incident_id = incident.incident_id
        create_incident(db, credential_type='aws_access_key', credential_hint='other',
                        repo_url='https://github.com/example/app', commit_hash='a' * 40,
                        exposure_start=now, project_id=project, forensic_tier=2)
        create_incident(db, credential_type='azure_service_principal', credential_hint='masked-azure',
                        principal_id=str(uuid4()), repo_url='https://github.com/example/app',
                        commit_hash='a' * 40, exposure_start=now, project_id=project)
    assert background_jobs.process_one()
    with sqlite_factory() as db:
        schedule = db.query(BackgroundJob).filter_by(dedupe_key=f'auto-refresh:{org}').one()
        jobs = db.query(BackgroundJob).filter_by(kind='incident_collect').all()
        assert schedule.status == 'queued' and schedule.attempts == 0
        assert schedule.result['queued'] == 1 and schedule.result['skipped'] == 2
        assert len(jobs) == 1 and jobs[0].payload['incident_id'] == incident_id
    second = auto_refresh.schedule_incidents(org)
    assert second['queued'] == 0 and second['skipped'] == 3
    with sqlite_factory() as db:
        assert db.query(BackgroundJob).filter_by(kind='incident_collect').count() == 1
        db.add(BackgroundJob(kind='incident_auto_refresh', dedupe_key=f'incident-auto:{incident_id}',
                             project_id=project, status='queued', available_at=now - timedelta(hours=1),
                             payload={'incident_id': incident_id, 'enabled': True, 'interval_minutes': 15}))
        db.commit()
    assert background_jobs.process_one()
    with sqlite_factory() as db:
        individual = db.query(BackgroundJob).filter_by(dedupe_key=f'incident-auto:{incident_id}').one()
        assert individual.status == 'queued' and individual.result['skipped'] == 1
        assert db.query(BackgroundJob).filter_by(kind='incident_collect').count() == 1


def test_disabled_schedule_does_not_enqueue(sqlite_factory, monkeypatch):
    import auto_refresh
    monkeypatch.setattr(auto_refresh, 'SessionLocal', sqlite_factory)
    assert auto_refresh.schedule_incidents(str(uuid4()))['queued'] == 0


def test_expired_schedule_lease_is_recovered(sqlite_factory, monkeypatch):
    import auto_refresh
    import background_jobs
    monkeypatch.setattr(background_jobs, 'SessionLocal', sqlite_factory)
    monkeypatch.setattr(auto_refresh, 'schedule_incidents', lambda _org: {'queued': 0, 'skipped': 0, 'last_run_at': '2026-01-01T00:00:00Z'})
    org_id = str(uuid4())
    now = datetime.now(timezone.utc)
    with sqlite_factory() as db:
        db.add(BackgroundJob(kind='auto_refresh', dedupe_key=f'auto-refresh:{org_id}', status='running',
                             payload={'organisation_id': org_id, 'enabled': True, 'interval_minutes': 60},
                             lease_token='old-lease', lease_until=now - timedelta(seconds=1), attempts=1,
                             available_at=now - timedelta(minutes=5)))
        db.commit()
    assert background_jobs.process_one()
    with sqlite_factory() as db:
        row = db.query(BackgroundJob).filter_by(dedupe_key=f'auto-refresh:{org_id}').one()
        assert row.status == 'queued' and row.lease_token is None and row.attempts == 0


def test_schedule_settings_are_persisted_and_role_protected(sqlite_factory):
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
    from routers import org as org_router
    org_id = str(uuid4())
    user = User(id=str(uuid4()), organisation_id=org_id, email='admin@example.test', full_name='Admin', role='org_admin')
    with sqlite_factory() as db:
        db.add(Organisation(id=org_id, name='Example', slug='example'))
        db.add(user)
        db.commit()
    app = FastAPI()
    app.include_router(org_router.router)
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[org_router.get_db] = database
    app.dependency_overrides[org_router.require_admin_or_lead] = lambda: user
    with TestClient(app) as client:
        assert client.get('/org/auto-refresh').json()['enabled'] is False
        assert client.put('/org/auto-refresh', json={'enabled': True, 'interval_minutes': 5}).status_code == 422
        response = client.put('/org/auto-refresh', json={'enabled': True, 'interval_minutes': 60})
        assert response.status_code == 410
        disabled = client.put('/org/auto-refresh', json={'enabled': False, 'interval_minutes': 60}).json()
        assert disabled['enabled'] is False and disabled['next_run_at'] is None
        def forbidden():
            raise HTTPException(403, 'Insufficient role')
        app.dependency_overrides[org_router.require_admin_or_lead] = forbidden
        assert client.put('/org/auto-refresh', json={'enabled': True, 'interval_minutes': 60}).status_code == 403
    with sqlite_factory() as db:
        row = db.query(BackgroundJob).filter_by(dedupe_key=f'auto-refresh:{org_id}').one()
        assert row.status == 'complete' and row.payload['enabled'] is False


def test_incident_schedules_are_independent(sqlite_factory):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routers import incidents
    org_id, actor_id, project_id = str(uuid4()), str(uuid4()), str(uuid4())
    user = User(id=actor_id, organisation_id=org_id, email='admin@example.test', full_name='Admin', role='org_admin')
    now = datetime.now(timezone.utc)
    with sqlite_factory() as db:
        db.add(Organisation(id=org_id, name='Example', slug='example'))
        db.add(user)
        db.add(Project(id=project_id, organisation_id=org_id, name='App', created_by=actor_id,
                       github_repo_url='https://github.com/example/app', github_repo_full_name='example/app'))
        db.commit()
        ids = []
        for tier in (1, 1, 2):
            incident = create_incident(db, credential_type='aws_access_key', credential_hint='masked',
                                       repo_url='https://github.com/example/app', commit_hash='a' * 40,
                                       exposure_start=now, project_id=project_id, forensic_tier=tier)
            ids.append(incident.incident_id)
    app = FastAPI()
    app.include_router(incidents.router)
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[incidents.get_db] = database
    app.dependency_overrides[incidents.get_active_user] = lambda: user
    app.dependency_overrides[incidents.require_admin_or_lead] = lambda: user
    with TestClient(app) as client:
        for incident_id, minutes in zip(ids[:2], (15, 120)):
            result = client.put(f'/incidents/{incident_id}/auto-refresh', json={'enabled': True, 'interval_minutes': minutes})
            assert result.status_code == 200 and result.json()['interval_minutes'] == minutes
        assert client.put(f'/incidents/{ids[2]}/auto-refresh', json={'enabled': True, 'interval_minutes': 60}).status_code == 422
        assert client.put(f'/incidents/{ids[0]}/auto-refresh', json={'enabled': False, 'interval_minutes': 15}).status_code == 200
        assert client.get(f'/incidents/{ids[1]}/auto-refresh').json()['interval_minutes'] == 120
        assert client.get(f'/incidents/{ids[1]}/auto-refresh').json()['enabled'] is True


def test_legacy_schedule_becomes_independent_incident_schedules(sqlite_factory, monkeypatch):
    import auto_refresh
    monkeypatch.setattr(auto_refresh, 'SessionLocal', sqlite_factory)
    org_id, actor_id, project_id = str(uuid4()), str(uuid4()), str(uuid4())
    now = datetime.now(timezone.utc)
    with sqlite_factory() as db:
        db.add(Organisation(id=org_id, name='Example', slug='example'))
        db.add(User(id=actor_id, organisation_id=org_id, email='admin@example.test', full_name='Admin', role='org_admin'))
        db.add(Project(id=project_id, organisation_id=org_id, name='App', created_by=actor_id,
                       github_repo_url='https://github.com/example/app', github_repo_full_name='example/app'))
        db.add(BackgroundJob(kind='auto_refresh', dedupe_key=f'auto-refresh:{org_id}', status='queued',
                             payload={'organisation_id': org_id, 'enabled': True, 'interval_minutes': 60}, available_at=now))
        db.commit()
        incident = create_incident(db, credential_type='aws_access_key', credential_hint='masked',
                                   repo_url='https://github.com/example/app', commit_hash='a' * 40,
                                   exposure_start=now, project_id=project_id)
        incident_id = incident.incident_id
    auto_refresh.migrate_legacy_schedules()
    auto_refresh.migrate_legacy_schedules()
    with sqlite_factory() as db:
        old = db.query(BackgroundJob).filter_by(dedupe_key=f'auto-refresh:{org_id}').one()
        new = db.query(BackgroundJob).filter_by(dedupe_key=f'incident-auto:{incident_id}').one()
        assert old.payload['enabled'] is False and new.payload['interval_minutes'] == 60
        assert db.query(BackgroundJob).filter_by(kind='incident_auto_refresh').count() == 1
