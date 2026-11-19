"""Snapshot promotion authorization, duplicate protection and timestamps."""
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from db.models import BackgroundJob, IncidentRecord, Organisation, Project, User
from routers import repositories


def test_snapshot_finding_can_be_added_once_to_its_project(sqlite_factory):
    observed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    scan_id, project_id, other_id = str(uuid4()), str(uuid4()), str(uuid4())
    user = User(id=str(uuid4()), organisation_id=str(uuid4()), email='admin@example.test', full_name='Admin', role='org_admin')
    fingerprint = 'a' * 64
    finding = {'fingerprint': fingerprint, 'credential_type': 'aws_access_key', 'credential_hint': 'masked'}
    with sqlite_factory() as db:
        db.add(Organisation(id=user.organisation_id, name='Example', slug='example'))
        db.add(user)
        db.add(Project(id=project_id, organisation_id=user.organisation_id, name='One', created_by=user.id,
                       github_repo_url='https://github.com/team/one', github_repo_full_name='team/one'))
        db.add(Project(id=other_id, organisation_id=user.organisation_id, name='Two', created_by=user.id,
                       github_repo_url='https://github.com/team/two', github_repo_full_name='team/two'))
        db.add(BackgroundJob(id=scan_id, kind='snapshot', status='complete', payload={}, updated_at=observed,
                             result={'repo_url': 'https://github.com/team/one', 'revision': 'b' * 40, 'findings': [finding]}))
        db.commit()
    app = FastAPI()
    app.include_router(repositories.router)
    app.dependency_overrides[repositories.local_operator] = lambda: None
    app.dependency_overrides[repositories.require_admin_or_lead] = lambda: user
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[repositories.get_db] = database
    with TestClient(app) as client:
        url = f'/repositories/scans/{scan_id}/findings/{fingerprint}/incident'
        assert client.post(url, json={'project_id': other_id}).status_code == 400
        added = client.post(url, json={'project_id': project_id})
        assert added.status_code == 201
        assert client.post(url, json={'project_id': project_id}).status_code == 409
        result = client.get(f'/repositories/scans/{scan_id}', params={'project_id': project_id}).json()
        assert result['possible_matches'][fingerprint] == added.json()['incident_id']
    with sqlite_factory() as db:
        incident = db.get(IncidentRecord, added.json()['incident_id'])
        assert incident.project_id == project_id and incident.forensic_tier == 2
        assert incident.access_key_id is None and incident.unavailable_reason.startswith('Snapshot observation:')
        assert incident.exposure_start.replace(tzinfo=timezone.utc) == observed
        assert db.query(IncidentRecord).count() == 1
