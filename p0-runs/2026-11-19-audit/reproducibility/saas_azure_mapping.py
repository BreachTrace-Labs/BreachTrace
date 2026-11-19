"""Offline Azure, Stripe and Twilio mapper/persistence fixture pilot."""
import csv
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as Obj

run = Path(__file__).resolve().parents[1]
root = Path(__file__).resolve().parents[3]
os.environ.update(DATABASE_URL='sqlite://', EMBED_ENABLED='false', MODEL_SETTINGS_FILE=str(run/'datasets/restricted/no-model-settings.json'))
sys.path.insert(0, str(root/'backend'))
def deny(*args, **kwargs): raise RuntimeError('network disabled')
socket.socket.connect = deny
socket.create_connection = deny
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base
from db.crud import create_incident, save_forensic_events
from collectors.azure import AzureActivityLogCollector
from collectors.stripe import StripeEventsCollector
from collectors.twilio import TwilioUsageCollector

ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
azure = object.__new__(AzureActivityLogCollector)
stripe = object.__new__(StripeEventsCollector)
twilio = object.__new__(TwilioUsageCollector)
def az(status):
    return Obj(event_timestamp=ts, operation_name=Obj(value='Microsoft.Example/read'),
               resource_provider_name=Obj(value='Microsoft.Example'), caller='principal-fixture',
               event_data_id='azure-fixture', status=Obj(value=status) if status else None)
def st(kind):
    return {'id':'evt_fixture','type':kind,'created':int(ts.timestamp()),'livemode':False,
            'request':{'id':'req_fixture'},'data':{'object':{'id':'obj_fixture','object':'payment_intent'}}}
def message(status):
    return Obj(date_sent=ts,date_created=ts,status=status,sid='SMfixture',account_sid='ACfixture',to='fixture')
def call(status):
    return Obj(start_time=ts,date_created=ts,status=status,sid='CAfixture',account_sid='ACfixture',to='fixture')
monitor=Obj(event_date=ts,event_type='fixture.event',sid='EVfixture',actor_sid='actor-fixture',resource_sid='resource-fixture')
fixtures=[('azure_success','azure','activity_log',True,'azure-fixture',azure._map_event(az('Succeeded'))),
          ('azure_missing_status','azure','activity_log',False,'azure-fixture',azure._map_event(az(None))),
          ('stripe_success','stripe','events',True,'evt_fixture',stripe._map_event(st('payment_intent.succeeded'))),
          ('stripe_failed','stripe','events',True,'evt_fixture',stripe._map_event(st('payment_intent.payment_failed'))),
          ('twilio_sent','twilio','messages',True,'SMfixture',twilio._map_message(message('sent'))),
          ('twilio_missing_status','twilio','messages',False,'SMfixture',twilio._map_message(message(None))),
          ('twilio_call_complete','twilio','calls',True,'CAfixture',twilio._map_call(call('completed'))),
          ('twilio_call_failed','twilio','calls',True,'CAfixture',twilio._map_call(call('failed'))),
          ('twilio_monitor','twilio','monitor',False,'EVfixture',twilio._map_monitor(monitor))]
engine=create_engine('sqlite://');Base.metadata.create_all(engine);rows=[]
with sessionmaker(bind=engine)() as db:
    for case,platform,mode,explicit_status,source_id,event in fixtures:
        incident=create_incident(db,credential_type={'azure':'azure_service_principal','stripe':'stripe_secret_key','twilio':'twilio_account'}[platform],credential_hint='fixture',repo_url='https://example.invalid/repo',commit_hash='a'*40,exposure_start=ts)
        persisted=save_forensic_events(db,incident.incident_id,[event])[0]
        raw=persisted.raw_data or {}
        rows.append({'case':case,'provider':platform,'mode':mode,'explicit_source_status':explicit_status,
                     'mapped_success':event.success,'persisted_success':persisted.success,
                     'mapped_operation':event.api_action,'principal_present':bool(event.principal_id),
                     'normalized_source_record_id_present':bool(persisted.source_record_id),
                     'source_id_in_raw_evidence':source_id in str(raw),
                     'exact_key_identifier_in_fixture':False})
path=Path(os.environ.get('P0_OUTPUT',str(run/'results/raw/saas-azure-mapping.csv')))
with path.open('x',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
print('Wrote',len(rows),'fixture observations.')
