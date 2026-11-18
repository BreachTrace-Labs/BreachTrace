"""Incident actions are project-scoped and recorded without secret data."""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from db.database import get_db
from db.crud import create_incident
from db.models import AuditLog


@pytest.fixture
def environment(sqlite_factory, monkeypatch):
    monkeypatch.setenv('JWT_SECRET_KEY','x'*64)
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY','12'*32)
    monkeypatch.setenv('BREACHTRACE_LOCAL_TEST_MODE','true')
    from main import app
    def database():
        with sqlite_factory() as db:
            yield db
    app.dependency_overrides[get_db] = database
    client = TestClient(app)
    yield client, sqlite_factory
    app.dependency_overrides.clear()


def test_dismiss_assignment_and_audit_permissions(environment):
    client, factory = environment
    client.post('/auth/register',json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    def login(email,password):
        return {'Authorization':'Bearer '+client.post('/auth/token',data={'username':email,'password':password}).json()['access_token']}
    admin=login('admin@example.com','admin password')
    def project(name):
        return client.post('/projects',headers=admin,json={'name':name,'github_repo_url':'https://github.com/acme/'+name}).json()['id']
    first,second=project('first'),project('second')
    developer=client.post('/org/users/invite',headers=admin,json={'email':'dev@example.com','full_name':'Dev','role':'developer','temporary_password':'dev password'}).json()['user_id']
    dev=login('dev@example.com','dev password')
    client.post('/auth/change-password',headers=dev,json={'current_password':'dev password','new_password':'new dev password'})
    client.post(f'/projects/{first}/members',headers=admin,json={'user_id':developer})
    with factory() as db:
        def incident(project_id):
            return create_incident(db,credential_type='github_pat',credential_hint='ghp_****test',repo_url='https://github.com/acme/first',commit_hash='a'*40,exposure_start=datetime.now(timezone.utc),project_id=project_id).incident_id
        a,b=incident(first),incident(second)
    assert client.post(f'/incidents/{a}/dismiss',headers=dev,json={'dismissal_type':'false_positive','reason':'short'}).status_code == 422
    assert client.post(f'/incidents/{b}/dismiss',headers=dev,json={'dismissal_type':'false_positive','reason':'test sample only'}).status_code == 403
    dismissal=client.post(f'/incidents/{a}/dismiss',headers=dev,json={'dismissal_type':'test_credential','reason':'Synthetic test fixture'})
    assert dismissal.status_code == 200
    assert dismissal.json()['dismissed_by_name']=='Dev'
    assert client.get('/incidents',headers=dev).json()[0]['dismissed'] is True
    assert client.post(f'/incidents/{a}/assign',headers=dev,json={'user_id':developer}).status_code == 403
    assert client.post(f'/incidents/{b}/assign',headers=admin,json={'user_id':developer}).status_code == 400
    assigned=client.post(f'/incidents/{a}/assign',headers=admin,json={'user_id':developer})
    assert assigned.status_code == 200 and assigned.json()['assigned_to_name']=='Dev'
    assert client.get(f'/incidents/{a}',headers=dev).status_code == 200
    assert client.get(f'/incidents/{a}/audit',headers=dev).status_code == 403
    rows=client.get(f'/incidents/{a}/audit',headers=admin).json()
    assert {'incident.viewed','incident.dismissed','incident.assigned'} <= {row['action'] for row in rows}
    assert 'Synthetic test fixture' not in str(rows)
    assert client.get('/org/audit',headers=dev).status_code == 403
    filtered=client.get('/org/audit',headers=admin,params={'action':'incident.dismissed','project_id':first,'limit':1}).json()
    assert len(filtered)==1 and filtered[0]['incident_id']==a
    assert client.get('/org/audit',headers=admin,params={'action':'incident.dismissed','offset':1}).json()==[]
    with factory() as db:
        assert db.query(AuditLog).filter_by(incident_id=b,action='incident.dismissed').count()==0


def test_queued_refresh_keeps_previous_evidence_and_report(environment):
    from crypto import encrypt_blob
    from db.crud import save_forensic_events
    from db.models import BackgroundJob, CredentialWalletEntry, ForensicEvent as StoredEvent, IncidentRecord
    from normalizer.schema import ForensicEvent
    client, factory = environment
    client.post('/auth/register', json={'org_name':'Acme', 'slug':'acme', 'admin_email':'admin@example.com',
                'admin_password':'admin password', 'admin_full_name':'Admin'})
    token = client.post('/auth/token', data={'username':'admin@example.com', 'password':'admin password'}).json()['access_token']
    headers = {'Authorization':'Bearer ' + token}
    project = client.post('/projects', headers=headers, json={'name':'App', 'github_repo_url':'https://github.com/acme/app'}).json()['id']
    ciphertext, iv = encrypt_blob({'auth_mode':'impersonation', 'project_id':'demo-project',
                                   'reader_service_account':'reader@demo-project.iam.gserviceaccount.com'})
    with factory() as db:
        db.add(CredentialWalletEntry(project_id=project, provider='gcp', encrypted_blob=ciphertext, iv=iv,
                                     created_by=client.get('/auth/me', headers=headers).json()['id'], verification_status='ok'))
        incident = create_incident(db, credential_type='gcp_service_account', credential_hint='worker...',
                                   principal_id='worker@demo-project.iam.gserviceaccount.com',
                                   repo_url='https://github.com/acme/app', commit_hash='a' * 40,
                                   exposure_start=datetime.now(timezone.utc), project_id=project)
        incident.status, incident.report_text = 'complete', 'Previous report'
        db.commit()
        save_forensic_events(db, incident.incident_id, [ForensicEvent(event_id='old-event', platform='gcp',
                             timestamp=datetime.now(timezone.utc), api_action='storage.objects.get', success=True)])
        incident_id = incident.incident_id
    assert client.post(f'/incidents/{incident_id}/refresh', headers=headers).status_code == 202
    with factory() as db:
        assert db.get(IncidentRecord, incident_id).status == 'collecting'
        assert db.get(IncidentRecord, incident_id).report_text == 'Previous report'
        assert db.query(StoredEvent).filter_by(incident_id=incident_id).one().event_id == 'old-event'
        job = db.query(BackgroundJob).filter_by(kind='incident_collect').one()
        assert job.payload['incident_id'] == incident_id and job.status == 'queued'


def test_refresh_and_snapshot_start_are_audited(environment, monkeypatch, tmp_path):
    client, factory = environment
    from routers import incidents, repositories
    client.post('/auth/register',json={'org_name':'Acme','slug':'acme','admin_email':'admin@example.com','admin_password':'admin password','admin_full_name':'Admin'})
    token=client.post('/auth/token',data={'username':'admin@example.com','password':'admin password'}).json()['access_token']
    admin={'Authorization':'Bearer '+token}
    project=client.post('/projects',headers=admin,json={'name':'app','github_repo_url':'https://github.com/acme/app'}).json()['id']
    from crypto import encrypt_blob
    from db.models import CredentialWalletEntry
    ciphertext, iv = encrypt_blob({'access_key_id':'AKIA' + 'A' * 16, 'secret_access_key':'secret', 'region':'us-east-1'})
    with factory() as db:
        db.add(CredentialWalletEntry(project_id=project, provider='aws', encrypted_blob=ciphertext, iv=iv,
                                     created_by=client.get('/auth/me', headers=admin).json()['id'], verification_status='ok'))
        db.commit()
        incident=create_incident(db,credential_type='aws_access_key',credential_hint='AKIA****TEST',access_key_id='AKIA1234567890123456',repo_url='https://github.com/acme/app',commit_hash='a'*40,exposure_start=datetime.now(timezone.utc),project_id=project)
        incident_id=incident.incident_id
    monkeypatch.setattr(incidents,'run_collection_pipeline',lambda *args, **kwargs: None)
    assert client.post(f'/incidents/{incident_id}/refresh',headers=admin).status_code==202
    monkeypatch.setattr(repositories,'_jobs',{})
    monkeypatch.setattr(repositories,'scan_github',lambda url: {'repo_url':url,'findings':[],'finding_count':0})
    monkeypatch.setattr(repositories,'__file__',str(tmp_path/'backend'/'routers'/'repositories.py'))
    from main import app
    local=TestClient(app,base_url='http://localhost',client=('127.0.0.1',1234))
    assert local.post('/repositories/scan',headers=admin,json={'repo_url':'https://github.com/acme/app'}).status_code==202
    with factory() as db:
        assert db.query(AuditLog).filter_by(action='incident.refreshed',incident_id=incident_id).count()==1
        assert db.query(AuditLog).filter_by(action='snapshot.started').count()==1
