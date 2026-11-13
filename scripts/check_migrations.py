"""Check fresh/populated upgrades in disposable databases on the local test server.

Uses .env.testing.local; refuses other servers. Never migrates an existing DB.
Run with .venv/bin/python scripts/check_migrations.py.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def main():
    from dotenv import dotenv_values
    from sqlalchemy import create_engine, inspect, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import Session
    from alembic import command
    from alembic.config import Config
    from db.models import ExperimentRun

    profile = dotenv_values(ROOT / ".env.testing.local")
    url = make_url(profile.get("DATABASE_URL") or "")
    if url.host != "127.0.0.1" or url.port != 55432 or url.database != "breachtrace_local_test":
        raise SystemExit("Refusing migration check outside the isolated local test server")
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    config = Config(str(ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "backend" / "migrations"))
    results = {}
    for scenario in ("fresh", "populated"):
        # Only this newly generated name is ever created/dropped by the check.
        name = "breachtrace_migration_check_" + uuid.uuid4().hex
        engine = None
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
        try:
            target = url.set(database=name)
            os.environ["DATABASE_URL"] = target.render_as_string(hide_password=False)
            engine = create_engine(target)
            if scenario == "populated":
                command.upgrade(config, "c4d5e6f7a8b9")
                with engine.begin() as connection:
                    connection.execute(text("""INSERT INTO experiment_runs
                        (run_id, run_number, group_label, access_key_id, commit_timestamp,
                         detection_latency_ms, report_latency_ms, event_count,
                         worst_category, overall_severity, notes)
                        VALUES ('legacy-research-run', 7, 'B', 'AKIA_SYNTHETIC_TEST',
                         '2026-01-01T00:00:00Z', 1420, 12345, 9,
                         'data_access', 3, 'preserve original research evidence')"""))
            command.upgrade(config, "head")
            assert inspect(engine).get_pk_constraint("experiment_runs")["constrained_columns"] == ["id"]
            if scenario == "fresh":
                command.downgrade(config, "c4d5e6f7a8b9")
                assert inspect(engine).get_pk_constraint("experiment_runs")["constrained_columns"] == ["run_id"]
                command.upgrade(config, "head")
            else:
                try:
                    command.downgrade(config, "c4d5e6f7a8b9")
                except RuntimeError as error:
                    assert "Cannot downgrade populated experiment_runs" in str(error)
                else:
                    raise AssertionError("Populated rollback must preserve current research rows")
                with engine.connect() as connection:
                    assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "e8f9a0b1c2d3"
            with Session(engine) as db:
                if scenario == "populated":
                    legacy = db.get(ExperimentRun, "legacy-research-run")
                    assert legacy.experiment_group == "B" and legacy.run_number == 7
                    assert legacy.detection_time_s == 1.42 and legacy.report_time_s == 12.345
                    assert legacy.overall_severity == "High" and legacy.impact_categories == ["data_access"]
                    assert legacy.exposure_start == datetime(2026, 1, 1, tzinfo=timezone.utc)
                    assert legacy.external_use_detected is False
                    archived = db.execute(text("SELECT * FROM experiment_runs_legacy_37cd4df9188c")).mappings().one()
                    assert archived["run_id"] == "legacy-research-run"
                    assert archived["event_count"] == 9 and archived["detection_latency_ms"] == 1420
                    assert archived["notes"] == "preserve original research evidence"
                run = ExperimentRun(experiment_group="A", platform="aws", detection_time_s=0.25)
                db.add(run)
                db.commit()
                assert db.get(ExperimentRun, run.id).detection_time_s == 0.25
            results[scenario] = "passed: upgrade, primary key, ORM insert" + (", legacy values/units/archive preserved, populated downgrade refused atomically" if scenario == "populated" else ", empty downgrade/re-upgrade")
        finally:
            if engine is not None:
                engine.dispose()
            with admin.connect() as connection:
                connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
    admin.dispose()
    output = ROOT / "data" / "migration-verification.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
