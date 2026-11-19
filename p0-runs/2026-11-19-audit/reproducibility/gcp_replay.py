"""Offline development replay of GCP mapping, SQLite and incident detail."""
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

run = Path(__file__).resolve().parents[1]
root = Path(__file__).resolve().parents[3]
os.environ['DATABASE_URL'] = 'sqlite:///' + str(run / 'datasets/restricted/replay.sqlite')
os.environ['MODEL_SETTINGS_FILE'] = str(run / 'datasets/restricted/no-model-settings.json')
os.environ['EMBED_ENABLED'] = 'false'
sys.path.insert(0, str(root / 'backend'))
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('network disabled'))
socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('network disabled'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base, GCPKeyAssociation
from db.crud import create_incident, save_forensic_events
from collectors.gcp import GCPAuditLogCollector
from gcp_attribution import key_digest
from reporter.facts import build_fact_sheet
from reporter.compose import deterministic_sections, render_report
from routers.incidents import get_incident_detail
from scorer.severity import score_incident

engine = create_engine(os.environ['DATABASE_URL'])
Base.metadata.create_all(engine)
when = datetime(2026, 1, 1, tzinfo=timezone.utc)
principal, a, b = 'worker@demo.iam.gserviceaccount.com', 'a' * 40, 'b' * 40
mapper = object.__new__(GCPAuditLogCollector)
events = []
for alias, key in [('target', a), ('sibling', b)]:
    payload = {'methodName': 'storage.objects.get', 'serviceName': 'storage.googleapis.com',
               'resourceName': 'projects/_/buckets/demo/objects/object', 'status': {'code': 0},
               'authenticationInfo': {'principalEmail': principal, 'serviceAccountKeyName':
                   f'//iam.googleapis.com/projects/demo/serviceAccounts/{principal}/keys/{key}'}}
    entry = SimpleNamespace(payload=payload, timestamp=when, resource=SimpleNamespace(type='gcs_bucket'),
                            insert_id=alias, log_name='projects/demo/logs/audit')
    events.append(mapper._map_entry(entry))
with sessionmaker(bind=engine)() as db:
    incident = create_incident(db, credential_type='gcp_service_account', credential_hint='demo',
                               repo_url='https://example.invalid/repo', commit_hash='a' * 40,
                               exposure_start=when, principal_id=principal, gcp_project_id='demo')
    db.add(GCPKeyAssociation(incident_id=incident.incident_id, key_digest=key_digest(a),
                             key_hint='synthetic', source='operator_reported'))
    db.commit()
    saved = save_forensic_events(db, incident.incident_id, events)
    incident.status = 'complete'
    # This severity is explicitly assigned by the replay via the actual helper.
    incident.overall_severity = score_incident(saved)
    db.commit()
    detail = get_incident_detail(incident.incident_id, db).model_dump(mode='json')
    facts = build_fact_sheet(saved, platform='gcp', overall_severity=incident.overall_severity,
                             exposure_duration_seconds=0, credential_type='gcp_service_account')
    report = render_report(facts, deterministic_sections(facts))
    output = {'source_mode': 'fixture', 'boundary': 'GCP mapper; incident route function; report helpers',
              'independent_review': 'pending', 'timeline': detail.get('events'),
              'blast_radius': detail.get('dynamic_blast_radius'), 'persisted_severity': incident.overall_severity,
              'fact_sheet': facts, 'deterministic_report': report}
    (run / 'results/raw/gcp-replay.json').write_text(json.dumps(output, indent=2, default=str) + '\n')
print('GCP replay output written.')
