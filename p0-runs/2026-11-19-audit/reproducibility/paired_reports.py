"""Run the existing timeline case design through the frozen GCP reporting pipeline."""
import csv
import hashlib
import json
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

run = Path(__file__).resolve().parents[1]
root = run.parents[1]
os.environ.update(DATABASE_URL="sqlite://", EMBED_ENABLED="false", MODEL_SETTINGS_FILE=str(run/"datasets/restricted/no-model-settings.json"))
sys.path.insert(0, str(root/"backend"))

def offline(*args, **kwargs):
    raise RuntimeError("Offline experiment")

socket.create_connection = socket.socket.connect = offline
import pipeline
from collectors.gcp import GCPAuditLogCollector
from db.crud import create_incident
from db.models import Base, GCPKeyAssociation, IncidentRecord
from gcp_attribution import key_digest
from routers.incidents import get_incident_detail
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

start = datetime(2026, 1, 1, tzinfo=timezone.utc)
class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        value = start + timedelta(hours=1)
        return value if tz else value.replace(tzinfo=None)

engine = create_engine("sqlite://")
Base.metadata.create_all(engine)
factory = sessionmaker(bind=engine)
source = run/"results/raw/timeline-decisions.csv"
principal = "worker@demo.iam.gserviceaccount.com"
mapper = object.__new__(GCPAuditLogCollector)

def replay(row):
    cluster = row["cluster"]
    target, sibling = ("a"*40, "b"*40) if row["case"].endswith("-0") else ("b"*40, "a"*40)
    actor = "other@demo.iam.gserviceaccount.com" if cluster == "unrelated" else principal
    key = target if row["truth"] == "target" else sibling
    auth = {"principalEmail": actor}
    if cluster != "missing":
        suffix = "malformed" if cluster == "malformed" else key
        auth["serviceAccountKeyName"] = f"//iam.googleapis.com/projects/demo/serviceAccounts/{actor}/keys/{suffix}"
    payload = dict(authenticationInfo=auth, methodName="storage.objects.get", serviceName="storage.googleapis.com",
                   resourceName="projects/_/buckets/demo/objects/object", status={"code": 0})
    entry = SimpleNamespace(payload=payload, timestamp=start, resource=SimpleNamespace(type="gcs_bucket"),
                            insert_id=row["case"], log_name="projects/demo/logs/audit")
    event = mapper._map_entry(entry)
    class Reader:
        def __init__(self, **kwargs): pass
        def collect(self, **kwargs): return [event]
        def close(self): pass
    with factory() as db:
        inc = create_incident(db, credential_type="gcp_service_account", credential_hint="fixture",
                              repo_url="https://example.invalid/repo", commit_hash="a"*40,
                              exposure_start=start, principal_id=principal, gcp_project_id="demo")
        iid = inc.incident_id
        if cluster != "no_association":
            db.add(GCPKeyAssociation(incident_id=iid, key_digest=key_digest(target), key_hint="fixture", source="operator_reported"))
            db.commit()
    with patch.dict(pipeline._COLLECTOR_MAP, gcp=Reader):
        pipeline.run_collection_pipeline(iid, principal, start, platform="gcp")
    with factory() as db:
        inc = db.get(IncidentRecord, iid)
        detail = get_incident_detail(iid, db)
        assert inc.status == "complete" and len(detail.events) == 1
        item = detail.events[0]
        assert item.source_record_id == event.source_record_id
        decision = {"matched":"target", "different_key":"other"}.get(item.gcp_key_attribution, "unknown")
        assert decision == row["decision"]
        return dict(case=row["case"], label=item.gcp_key_attribution, record=item.source_record_id,
                    severity=inc.overall_severity, blast=detail.model_dump(mode="json")["dynamic_blast_radius"],
                    report=inc.report_text, actor_matches_incident=actor==principal)

if __name__ == "__main__":
    began = datetime.now(timezone.utc)
    with source.open() as stream, patch.multiple(pipeline, SessionLocal=factory, datetime=Clock,
            project_reader=lambda *a: None, _index_incident_safely=lambda *a: None, _upgrade_report=lambda *a: False):
        results = [replay(row) for row in csv.DictReader(stream) if row["arm"] == "BT"]
    assert len(results) == 12
    output = json.dumps(results, indent=2) + "\n"
    destination = Path(os.environ.get("P0_OUTPUT", str(run/"results/raw/paired-reports.json")))
    with destination.open("x") as f: f.write(output)
    print(began.isoformat(), datetime.now(timezone.utc).isoformat(), hashlib.sha256(output.encode()).hexdigest())
