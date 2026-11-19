"""Run one inert GCP case through the frozen collection pipeline offline."""
import json
import os
import socket
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace

run = Path(__file__).resolve().parents[1]
root = Path(__file__).resolve().parents[3]
os.environ.update(DATABASE_URL='sqlite://', MODEL_SETTINGS_FILE=str(run / 'datasets/restricted/no-model-settings.json'), EMBED_ENABLED='false')
sys.path.insert(0, str(root / 'backend'))
def deny(*args, **kwargs):
    raise RuntimeError('network disabled')
socket.create_connection = deny
socket.socket.connect = deny

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from db.models import Base, GCPKeyAssociation, IncidentRecord
from db.crud import create_incident
from collectors.gcp import GCPAuditLogCollector
from gcp_attribution import key_digest
from routers.incidents import get_incident_detail
import pipeline

engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
Base.metadata.create_all(engine)
factory = sessionmaker(bind=engine, expire_on_commit=False)
start = datetime(2026, 1, 1, tzinfo=timezone.utc)
principal, target, sibling = 'worker@demo.iam.gserviceaccount.com', 'a' * 40, 'b' * 40
mapper = object.__new__(GCPAuditLogCollector)
events = []
for label, key in [('target', target), ('sibling', sibling)]:
    payload = {'methodName': 'storage.objects.get', 'serviceName': 'storage.googleapis.com',
               'resourceName': 'projects/_/buckets/demo/objects/object', 'status': {'code': 0},
               'authenticationInfo': {'principalEmail': principal, 'serviceAccountKeyName':
                   f'//iam.googleapis.com/projects/demo/serviceAccounts/{principal}/keys/{key}'}}
    entry = SimpleNamespace(payload=payload, timestamp=start, resource=SimpleNamespace(type='gcs_bucket'),
                            insert_id=label, log_name='projects/demo/logs/audit')
    events.append(mapper._map_entry(entry))

class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        value = start + timedelta(hours=1)
        return value if tz else value.replace(tzinfo=None)

class StubCollector:
    def __init__(self, **kwargs): pass
    def collect(self, **kwargs): return events
    def close(self): pass

captured = {}
real_build = pipeline.build_fact_sheet
def capture_facts(*args, **kwargs):
    captured.update(real_build(*args, **kwargs))
    return captured

pipeline.SessionLocal = factory
pipeline.datetime = FixedDateTime
pipeline._COLLECTOR_MAP = {**pipeline._COLLECTOR_MAP, 'gcp': StubCollector}
pipeline.project_reader = lambda *args: None
pipeline._index_incident_safely = lambda *args: None
pipeline._upgrade_report = lambda *args: False
pipeline.build_fact_sheet = capture_facts
with factory() as db:
    incident = create_incident(db, credential_type='gcp_service_account', credential_hint='fixture',
                               repo_url='https://example.invalid/repo', commit_hash='a' * 40,
                               exposure_start=start, principal_id=principal, gcp_project_id='demo')
    db.add(GCPKeyAssociation(incident_id=incident.incident_id, key_digest=key_digest(target),
                             key_hint='synthetic', source='operator_reported'))
    db.commit()
    incident_id = incident.incident_id
pipeline.run_collection_pipeline(incident_id, principal, start, platform='gcp')
with factory() as db:
    incident = db.get(IncidentRecord, incident_id)
    detail = get_incident_detail(incident_id, db).model_dump(mode='json')
    output = {'source_mode': 'fixture', 'status': incident.status, 'timeline': detail.get('events'),
              'blast_radius': detail.get('dynamic_blast_radius'), 'persisted_severity': incident.overall_severity,
              'report_source': incident.report_source, 'persisted_report': incident.report_text,
              'pipeline_fact_sheet': captured, 'review': 'independent adjudication pending'}
    destination = Path(os.environ.get('P0_OUTPUT', str(run / 'results/raw/gcp-pipeline-replay.json')))
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(output, stream, indent=2, default=str)
        stream.write('\n')
    print('Pipeline status:', incident.status)
