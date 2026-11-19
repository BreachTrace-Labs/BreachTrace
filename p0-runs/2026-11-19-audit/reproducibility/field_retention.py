"""Offline field-presence pilot through GCP/AWS mapper and persistence."""
import csv
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

run = Path(__file__).resolve().parents[1]
root = Path(__file__).resolve().parents[3]
os.environ.update(DATABASE_URL='sqlite://', EMBED_ENABLED='false', MODEL_SETTINGS_FILE=str(run / 'datasets/restricted/no-model-settings.json'))
sys.path.insert(0, str(root / 'backend'))
def deny(*args, **kwargs): raise RuntimeError('network disabled')
socket.socket.connect = deny
socket.create_connection = deny
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base
from db.crud import create_incident, save_forensic_events
from collectors.gcp import GCPAuditLogCollector
from collectors.aws import _map_cloudtrail_event, _map_trail_record

engine = create_engine('sqlite://')
Base.metadata.create_all(engine)
now = datetime(2026, 1, 1, tzinfo=timezone.utc)
principal = 'worker@demo.iam.gserviceaccount.com'
key_name = f'//iam.googleapis.com/projects/demo/serviceAccounts/{principal}/keys/' + 'a' * 40
mapper = object.__new__(GCPAuditLogCollector)
def gcp(with_key):
    auth = {'principalEmail': principal}
    if with_key: auth['serviceAccountKeyName'] = key_name
    payload = {'authenticationInfo': auth, 'methodName':'storage.objects.get', 'serviceName':'storage.googleapis.com', 'status':{'code':0}}
    return mapper._map_entry(SimpleNamespace(payload=payload, timestamp=now, resource=SimpleNamespace(type='gcs_bucket'), insert_id='one', log_name='projects/demo/logs/audit'))
identity = {'arn':'arn:aws:iam::000000000000:user/fixture', 'accessKeyId':'AKIA' + 'A' * 16}
nested = {'eventID':'example', 'eventTime':now.isoformat(), 'eventName':'GetObject', 'eventSource':'s3.amazonaws.com', 'userIdentity':identity}
lookup = {'EventId':'example', 'EventTime':now, 'EventName':'GetObject', 'EventSource':'s3.amazonaws.com', 'CloudTrailEvent':json.dumps(nested)}
fixtures = [('gcp_key','gcp',gcp(True),True,True), ('gcp_missing_key','gcp',gcp(False),True,False),
            ('aws_lookup','aws',_map_cloudtrail_event(lookup),True,True), ('aws_trail','aws',_map_trail_record(nested,'fixture','fixture','0'*64),True,True)]
def mask(event, platform):
    raw = event.raw_data or {}
    if platform == 'gcp':
        auth = raw.get('authenticationInfo') or {}
        principal_present = bool(auth.get('principalEmail'))
        key_present = bool(auth.get('serviceAccountKeyName'))
    else:
        nested_value = raw.get('CloudTrailEvent')
        inner = json.loads(nested_value) if isinstance(nested_value, str) else {}
        auth = inner.get('userIdentity') or {}
        principal_present = bool(auth.get('arn'))
        key_present = bool(auth.get('accessKeyId'))
    return {'record_id':bool(event.source_record_id), 'principal':principal_present, 'key':key_present,
            'operation':bool(event.api_action), 'timestamp':event.timestamp is not None, 'outcome':event.success is not None}

observations=[]
with sessionmaker(bind=engine)() as db:
    for case, platform, event, principal_present, key_present in fixtures:
        # The AWS fixtures have no explicit outcome field; absence of an error is not a field.
        source={'record_id':True,'principal':principal_present,'key':key_present,'operation':True,'timestamp':True,'outcome':platform=='gcp'}
        incident=create_incident(db,credential_type='gcp_service_account' if platform=='gcp' else 'aws_access_key',credential_hint='fixture',repo_url='https://example.invalid/repo',commit_hash='a'*40,exposure_start=now)
        before=mask(event,platform)
        stored=save_forensic_events(db,incident.incident_id,[event])[0]
        after=mask(stored,platform)
        for field in source:
            observations.append({'case':case,'source_mode':case,'field':field,'source_present':source[field], 'normalized_present':before[field], 'persisted_present':after[field]})
destination = Path(os.environ.get('P0_OUTPUT', str(run/'results/raw/field-retention.csv')))
with destination.open('x',newline='') as f:
    w=csv.DictWriter(f,fieldnames=observations[0]);w.writeheader();w.writerows(observations)
print('Wrote',len(observations),'field observations from',len(fixtures),'fixture records.')
