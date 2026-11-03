"""Export masked preview fixtures and seed the isolated local UI database."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def main():
    from research.ai_demo import demo_incidents, seed_incidents
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-only", action="store_true")
    args = parser.parse_args()
    fixtures = demo_incidents()
    target = ROOT / "client" / "src" / "api" / "aiDemoIncidents.json"
    target.write_text(json.dumps(fixtures, indent=2) + "\n")
    if not args.export_only:
        from dotenv import load_dotenv
        from sqlalchemy.engine import make_url
        load_dotenv(ROOT / ".env.testing.local", override=True)
        url = make_url(os.environ.get("DATABASE_URL") or "")
        if url.host != "127.0.0.1" or url.port != 55432 or url.database != "breachtrace_local_test":
            raise SystemExit("Refusing demo seeding outside the isolated local test database")
        from db.database import SessionLocal
        from rag.index import index_incident
        with SessionLocal() as db:
            seed_incidents(db)
            for fixture in fixtures:
                index_incident(db, fixture["incident_id"])
    print(json.dumps({"count": len(fixtures), "export_only": args.export_only,
                      "demo_incident_ids": {f["platform"]: f["incident_id"] for f in fixtures}}, indent=2))


if __name__ == "__main__":
    main()
