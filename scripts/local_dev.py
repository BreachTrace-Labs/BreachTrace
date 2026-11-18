"""Local test profile and sample data; existing .env and databases stay intact.

Use the project venv: .venv/bin/python scripts/local_dev.py prepare|bootstrap|backend|frontend
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / ".env.testing.local"
sys.path.insert(0, str(ROOT / "backend"))


def prepare():
    if PROFILE.exists():
        print("Local test profile already exists; preserving it.")
        return
    password = secrets.token_hex(24)
    settings = {
        "LOCAL_DB_PASSWORD": password,
        "DATABASE_URL": f"postgresql+psycopg2://breachtrace_test:{password}@127.0.0.1:55432/breachtrace_local_test",
        "BREACHTRACE_LOCAL_TEST_MODE": "true", "ENVIRONMENT": "development",
        "REPORT_PROVIDER": "none", "REPORT_MODEL_ENABLED": "false", "EMBED_ENABLED": "true",
        "MODEL_CACHE_DIR": str(ROOT / "data" / "models"),
        "MODEL_SETTINGS_FILE": str(ROOT / "data" / "model-settings.testing.json"),
        "GITHUB_WEBHOOK_SECRET": secrets.token_hex(32),
        "AWS_EC2_METADATA_DISABLED": "true",
        "GITHUB_TOKEN": "", "GITHUB_TEST_REPO": "",
        "AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": "", "AWS_REGION": "us-east-1",
        "EXPERIMENT_AWS_ACCESS_KEY_ID": "", "EXPERIMENT_AWS_SECRET_ACCESS_KEY": "",
        "GCP_PROJECT_ID": "", "GCP_SERVICE_ACCOUNT_JSON": "",
        "AZURE_TENANT_ID": "", "AZURE_CLIENT_ID": "", "AZURE_CLIENT_SECRET": "", "AZURE_SUBSCRIPTION_ID": "",
        "STRIPE_API_KEY": "", "TWILIO_ACCOUNT_SID": "", "TWILIO_AUTH_TOKEN": "",
        "GEMINI_API_KEY": "", "OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": "",
    }
    fd = os.open(PROFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("# Isolated local testing. No production/cloud credentials.\n")
        for key, value in settings.items():
            stream.write(f"{key}={value}\n")
    print("Created gitignored local test profile; no secrets printed.")


def load_profile():
    from dotenv import load_dotenv
    if not PROFILE.exists():
        raise SystemExit("Run prepare first")
    load_dotenv(PROFILE, override=True)


def ensure_local_organisation_index(engine):
    """Upgrade ORM-bootstrapped local databases without stamping migrations."""
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    if 'uq_organisation_singleton' in {item['name'] for item in inspector.get_indexes('organisations')}:
        return
    if inspector.has_table('alembic_version'):
        raise SystemExit('This database uses Alembic. Apply migrations before local bootstrap.')
    with engine.begin() as connection:
        if connection.execute(text('SELECT COUNT(*) FROM organisations')).scalar_one() > 1:
            raise SystemExit('This database contains multiple organisations. Back it up and resolve them before local bootstrap.')
        connection.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uq_organisation_singleton ON organisations ((1))'))


def bootstrap():
    load_profile()
    from sqlalchemy.engine import make_url
    url = make_url(os.environ["DATABASE_URL"])
    if url.database != "breachtrace_local_test" or url.host not in {"localhost", "127.0.0.1"} or url.port != 55432:
        raise SystemExit("Refusing schema setup outside the isolated local test database")
    from db.database import engine, SessionLocal
    from db.models import Base, IncidentRecord
    from db.crud import create_incident, save_forensic_events
    from classifier.rules import classify_events
    from normalizer.schema import ForensicEvent
    from reporter.compose import deterministic_sections, render_report
    from reporter.facts import build_fact_sheet
    from reporter.remediation import build_remediation
    from rag.index import ensure_kb, index_incident
    from scorer.severity import score_incident

    # Fresh, dedicated test DB only. Do not stamp or modify the migration chain.
    Base.metadata.create_all(engine)
    ensure_local_organisation_index(engine)
    with SessionLocal() as db:
        existing = db.query(IncidentRecord).filter(IncidentRecord.commit_hash == "synthetic-local-test-v1").first()
        if existing is None:
            start = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
            incident = create_incident(
                db, credential_type="aws_access_key", credential_hint="AKIA****TEST",
                access_key_id=None, repo_url="local-test://synthetic-forensic-timeline",
                commit_hash="synthetic-local-test-v1", exposure_start=start,
            )
            events = [ForensicEvent(
                platform="aws", timestamp=start + timedelta(seconds=offset), api_action=action,
                event_source="s3.amazonaws.com", affected_resource="synthetic-test-bucket/report.csv",
                source_ip="192.0.2.10", success=success,
                error_code=None if success else "AccessDenied",
                raw_data={"synthetic": True, "purpose": "local UI testing; not research evidence"},
            ) for offset, action, success in [(0, "ListBuckets", True), (30, "GetObject", True), (60, "DeleteObject", False)]]
            classify_events(events)
            severity = score_incident(events)
            save_forensic_events(db, incident.incident_id, events)
            facts = build_fact_sheet(events, platform="aws", overall_severity=severity,
                                     exposure_duration_seconds=120, credential_type=incident.credential_type,
                                     credential_hint=incident.credential_hint)
            incident.report_text = "**SYNTHETIC LOCAL TEST DATA — not real cloud activity or research evidence.**\n\n" + render_report(facts, deterministic_sections(facts))
            incident.report_source = "deterministic"
            incident.remediation_steps = build_remediation(facts)
            incident.exposure_end = start + timedelta(seconds=120)
            incident.overall_severity = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[severity]
            incident.status = "complete"
            db.commit()
            index_incident(db, incident.incident_id)
            print("Added clearly labelled synthetic timeline/report fixture.")
        else:
            print("Synthetic fixture already exists; preserving data.")
        ensure_kb(db)
    print("Local test schema and search index ready.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "bootstrap", "backend", "frontend"])
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "bootstrap":
        bootstrap()
    elif args.command == "backend":
        load_profile()
        import uvicorn
        uvicorn.run("main:app", host="127.0.0.1", port=8000, proxy_headers=False)
    else:
        env = dict(os.environ, VITE_API_URL="http://127.0.0.1:8000", VITE_USE_MOCK="false")
        raise SystemExit(subprocess.call(["npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173", "--strictPort"], cwd=ROOT / "client", env=env))


if __name__ == "__main__":
    main()
