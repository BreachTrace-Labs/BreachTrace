"""GCP incident timeline attribution on inert paired development cases."""
import csv, os, re, socket, sys
from datetime import datetime, timezone
from pathlib import Path
run=Path(__file__).resolve().parents[1];root=Path(__file__).resolve().parents[3]
os.environ.update(DATABASE_URL='sqlite://',EMBED_ENABLED='false',MODEL_SETTINGS_FILE=str(run/'datasets/restricted/no-model-settings.json'))
sys.path.insert(0,str(root/'backend'))
def deny(*args,**kwargs): raise RuntimeError('network disabled')
socket.socket.connect=deny;socket.create_connection=deny
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base,GCPKeyAssociation
from db.crud import create_incident,save_forensic_events
from normalizer.schema import ForensicEvent
from routers.incidents import get_incident_detail
from gcp_attribution import key_digest

engine=create_engine('sqlite://');Base.metadata.create_all(engine)
now=datetime(2026,1,1,tzinfo=timezone.utc);principal='worker@demo.iam.gserviceaccount.com';other='other@demo.iam.gserviceaccount.com'
pattern=re.compile(r'^//iam\.googleapis\.com/projects/[^/]+/serviceAccounts/([^/]+)/keys/([a-fA-F0-9]{40})$')
rows=[]
with sessionmaker(bind=engine)() as db:
    for scenario in ('target','sibling','missing','malformed','unrelated','no_association'):
        for world in (0,1):
            key_a,key_b=('a'*40,'b'*40) if world==0 else ('b'*40,'a'*40)
            truth=('target' if scenario=='target' else 'other' if scenario in ('sibling','unrelated') else ('target' if world==0 else 'other'))
            actor=other if scenario=='unrelated' else principal
            key=key_a if truth=='target' else key_b
            auth={'principalEmail':actor}
            if scenario!='missing': auth['serviceAccountKeyName']=f'//iam.googleapis.com/projects/demo/serviceAccounts/{actor}/keys/'+('malformed' if scenario=='malformed' else key)
            incident=create_incident(db,credential_type='gcp_service_account',credential_hint='fixture',repo_url='https://example.invalid/repo',commit_hash='a'*40,exposure_start=now,principal_id=principal,gcp_project_id='demo')
            if scenario!='no_association':db.add(GCPKeyAssociation(incident_id=incident.incident_id,key_digest=key_digest(key_a),key_hint='fixture',source='operator_reported'));db.commit()
            event=ForensicEvent(platform='gcp',timestamp=now,api_action='storage.objects.get',raw_data={'authenticationInfo':auth},principal_id=actor)
            save_forensic_events(db,incident.incident_id,[event])
            detail=get_incident_detail(incident.incident_id,db)
            badge=detail.events[0].gcp_key_attribution
            bt={'matched':'target','different_key':'other','unavailable':'unknown',None:'unknown'}[badge]
            match=pattern.fullmatch(auth.get('serviceAccountKeyName',''))
            native='unknown'
            if scenario!='no_association' and actor==principal and match and match.group(1)==actor:
                native='target' if match.group(2)==key_a else 'other'
            decisions={'BT':bt,'B0_abstain':'unknown','B1_principal_time':'target' if actor==principal else 'unknown','B2_native_fields':native}
            for arm,decision in decisions.items():
                rows.append({'cluster':scenario,'case':f'{scenario}-{world}','truth':truth,'arm':arm,'decision':decision,
                             'warranted_target':decision=='target' and native=='target','wrong_key':decision=='target' and truth=='other',
                             'source_mode':'fixture','review':'pending'})
destination=Path(os.environ.get('P0_OUTPUT',str(run/'results/raw/timeline-decisions.csv')))
with destination.open('x',newline='') as f:w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
print('Recorded',len(rows),'decisions across 12 related fixture incidents.')
