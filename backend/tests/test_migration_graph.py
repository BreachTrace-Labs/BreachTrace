"""Validate the revision graph without connecting to any database."""
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.migration import MigrationContext
from alembic.operations import Operations
import importlib.util
import pytest
import sqlalchemy as sa


def test_migrations_have_one_connected_head_and_no_missing_revisions():
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["d52a0f18b721"]
    revisions = list(scripts.walk_revisions())
    assert revisions[-1].down_revision is None
    assert "37cd4df9188c" in {revision.revision for revision in revisions}


def test_gcp_key_source_migration_preserves_manual_associations():
    path = Path(__file__).resolve().parents[1] / 'migrations' / 'versions' / 'cc84e119d320_gcp_detected_key.py'
    spec = importlib.util.spec_from_file_location('gcp_detected_key_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE users (id VARCHAR(36) PRIMARY KEY)')
        connection.exec_driver_sql('CREATE TABLE incident_records (incident_id VARCHAR(36) PRIMARY KEY)')
        connection.exec_driver_sql('CREATE TABLE gcp_key_associations (incident_id VARCHAR(36) PRIMARY KEY REFERENCES incident_records(incident_id), key_digest VARCHAR(64) NOT NULL, key_hint VARCHAR(20) NOT NULL, recorded_by VARCHAR(36) NOT NULL REFERENCES users(id), recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)')
        connection.exec_driver_sql("INSERT INTO users (id) VALUES ('operator')")
        connection.exec_driver_sql("INSERT INTO incident_records (incident_id) VALUES ('manual'), ('automatic')")
        connection.exec_driver_sql("INSERT INTO gcp_key_associations (incident_id, key_digest, key_hint, recorded_by) VALUES ('manual', 'digest', 'hint', 'operator')")
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            rows = connection.exec_driver_sql('SELECT recorded_by, source FROM gcp_key_associations').all()
            assert rows == [('operator', 'operator_reported')]
            connection.exec_driver_sql("INSERT INTO gcp_key_associations (incident_id, key_digest, key_hint, recorded_by, source) VALUES ('automatic', 'digest', 'hint', NULL, 'detected_in_commit')")
            migration.downgrade()
        assert connection.exec_driver_sql('SELECT incident_id, recorded_by FROM gcp_key_associations').all() == [('manual', 'operator')]


def test_gcp_record_identity_migration_preserves_existing_events():
    path = Path(__file__).resolve().parents[1] / 'migrations' / 'versions' / 'd52a0f18b721_gcp_record_identity.py'
    spec = importlib.util.spec_from_file_location('gcp_record_identity_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE forensic_events (event_id VARCHAR(36) PRIMARY KEY, incident_id VARCHAR(36) NOT NULL)')
        connection.exec_driver_sql("INSERT INTO forensic_events (event_id, incident_id) VALUES ('old', 'incident')")
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            assert connection.exec_driver_sql('SELECT event_id, source_record_id FROM forensic_events').all() == [('old', None)]
            connection.exec_driver_sql("INSERT INTO forensic_events VALUES ('first', 'incident', 'source')")
            with pytest.raises(sa.exc.IntegrityError):
                connection.exec_driver_sql("INSERT INTO forensic_events VALUES ('duplicate', 'incident', 'source')")
            connection.exec_driver_sql("INSERT INTO forensic_events VALUES ('other', 'other-incident', 'source')")
            migration.downgrade()
        assert connection.exec_driver_sql('SELECT COUNT(*) FROM forensic_events').scalar_one() == 3
