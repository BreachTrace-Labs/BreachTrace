"""Offline pipeline development cases for Azure, Stripe, and Twilio."""
import json
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as Obj

run=Path(__file__).resolve().parents[1]; root=Path(__file__).resolve().parents[3]
os.environ.update(DATABASE_URL='sqlite://', EMBED_ENABLED='false', MODEL_SETTINGS_FILE=str(run/'datasets/restricted/no-model-settings.json'))
sys.path.insert(0,str(root/'backend'))
def deny(*args,**kwargs): raise RuntimeError('network disabled')
socket.socket.connect=deny;socket.create_connection=deny
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from db.models import Base, IncidentRecord
from db.crud import create_incident
from collectors.azure import AzureActivityLogCollector
from collectors.stripe import StripeEventsCollector
from collectors.twilio import TwilioUsageCollector
from routers.incidents import get_incident_detail
import pipeline

now=datetime(2026,1,1,tzinfo=timezone.utc)
class FixedDateTime(datetime):
    @classmethod
    def now(cls,tz=None):
        t=now+timedelta(hours=1)
        return t if tz else t.replace(tzinfo=None)
azure=object.__new__(AzureActivityLogCollector);stripe=object.__new__(StripeEventsCollector);twilio=object.__new__(TwilioUsageCollector)
az=Obj(event_timestamp=now,operation_name=Obj(value='Microsoft.Example/read'),resource_provider_name=Obj(value='Microsoft.Example'),caller='principal-fixture',event_data_id='azure-fixture',status=Obj(value='Succeeded'))
st={'id':'evt_fixture','type':'payment_intent.succeeded','created':int(now.timestamp()),'livemode':False,'request':{'id':'req_fixture'},'data':{'object':{'id':'pi_fixture','object':'payment_intent','amount':100,'currency':'usd','status':'succeeded'}}}
message=Obj(date_sent=now,date_created=now,status='sent',sid='SMfixture',account_sid='ACfixture',to='fixture',direction='outbound-api')
cases=[('azure','azure_service_principal',azure._map_event(az)),('stripe','stripe_secret_key',stripe._map_event(st)),('twilio','twilio_account_sid',twilio._map_message(message))]
engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool); Base.metadata.create_all(engine)
factory=sessionmaker(bind=engine,expire_on_commit=False)
pipeline.SessionLocal=factory;pipeline.datetime=FixedDateTime;pipeline.project_reader=lambda *args:None
pipeline._index_incident_safely=lambda *args:None;pipeline._upgrade_report=lambda *args:False
real_build=pipeline.build_fact_sheet
outputs=[]
for platform,kind,event in cases:
    captured={}
    def build(*args,**kwargs):
        captured.update(real_build(*args,**kwargs));return captured
    class Collector:
        def __init__(self,**kwargs): pass
        def collect(self,**kwargs): return [event]
        def close(self): pass
    pipeline.build_fact_sheet=build;pipeline._COLLECTOR_MAP={**pipeline._COLLECTOR_MAP,platform:Collector}
    try:
        with factory() as db:
            incident=create_incident(db,credential_type=kind,credential_hint='fixture',repo_url='https://example.invalid/repo',commit_hash='a'*40,exposure_start=now,principal_id='principal-fixture')
            incident_id=incident.incident_id
        pipeline.run_collection_pipeline(incident_id,'fixture',now,platform=platform)
        with factory() as db:
            incident=db.get(IncidentRecord,incident_id); detail=get_incident_detail(incident_id,db).model_dump(mode='json')
            outputs.append({'provider':platform,'status':incident.status,'timeline':detail.get('events'),'blast_radius':detail.get('dynamic_blast_radius'),
                            'persisted_severity':incident.overall_severity,'report_source':incident.report_source,
                            'persisted_report':incident.report_text,'pipeline_fact_sheet':captured,'review':'independent adjudication pending'})
    except Exception as exc:
        outputs.append({'provider':platform,'status':'replay_error','error_type':type(exc).__name__,'review':'not available'})
destination=Path(os.environ.get('P0_OUTPUT',str(run/'results/raw/provider-pipelines.json')))
with destination.open('x',encoding='utf-8') as stream:json.dump(outputs,stream,indent=2,default=str);stream.write('\n')
print('Provider statuses:',', '.join(x['provider']+'='+x['status'] for x in outputs))
