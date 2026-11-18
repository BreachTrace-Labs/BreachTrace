"""Existing bootstrap tables must be verified, never silently overwritten."""
import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from migrations import schema_reconcile


def expected_columns():
    return (sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('status', sa.String(20), nullable=False, server_default='queued'),
            sa.CheckConstraint("status IN ('queued','complete')", name='ck_status'))


def test_compatible_existing_table_and_index_are_preserved(monkeypatch):
    monkeypatch.setattr(schema_reconcile.context, 'is_offline_mode', lambda: False)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE task (id VARCHAR(36) PRIMARY KEY NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'queued', CONSTRAINT ck_status CHECK (status IN ('queued','complete')))")
        connection.exec_driver_sql("INSERT INTO task (id) VALUES ('existing')")
        with Operations.context(MigrationContext.configure(connection)):
            schema_reconcile.ensure_table('task', *expected_columns())
            schema_reconcile.ensure_index('ix_task_status', 'task', ['status'])
            schema_reconcile.ensure_index('ix_task_status', 'task', ['status'])
        assert connection.exec_driver_sql('SELECT id FROM task').scalars().all() == ['existing']


@pytest.mark.parametrize('definition', [
    "id VARCHAR(36) PRIMARY KEY NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'wrong', CONSTRAINT ck_status CHECK (status IN ('queued','complete'))",
    "id VARCHAR(36) PRIMARY KEY NOT NULL, status VARCHAR(30) NOT NULL DEFAULT 'queued', CONSTRAINT ck_status CHECK (status IN ('queued','complete'))",
    "id VARCHAR(36) PRIMARY KEY NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'queued', CONSTRAINT ck_status CHECK (status NOT IN ('queued','complete'))",
    "id VARCHAR(36) PRIMARY KEY NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'queued', CONSTRAINT ck_status CHECK (status IN ('queued','complete') OR 1=1)",
])
def test_conflicting_table_is_rejected_without_modification(monkeypatch, definition):
    monkeypatch.setattr(schema_reconcile.context, 'is_offline_mode', lambda: False)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE TABLE task ({definition})')
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match='incompatible'):
                schema_reconcile.ensure_table('task', *expected_columns())


def test_mismatched_index_is_rejected(monkeypatch):
    monkeypatch.setattr(schema_reconcile.context, 'is_offline_mode', lambda: False)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE task (id VARCHAR(36), status VARCHAR(20))')
        connection.exec_driver_sql('CREATE UNIQUE INDEX ix_task_status ON task (status)')
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match='does not match'):
                schema_reconcile.ensure_index('ix_task_status', 'task', ['status'])


def test_partial_index_is_not_mistaken_for_a_complete_index(monkeypatch):
    monkeypatch.setattr(schema_reconcile.context, 'is_offline_mode', lambda: False)
    engine = sa.create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE task (id VARCHAR(36), status VARCHAR(20))')
        connection.exec_driver_sql("CREATE INDEX ix_task_status ON task (status) WHERE status = 'queued'")
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match='does not match'):
                schema_reconcile.ensure_index('ix_task_status', 'task', ['status'])
