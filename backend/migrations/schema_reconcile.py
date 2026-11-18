"""Safely reconcile migrations with tables created by an earlier local bootstrap.

Existing objects are accepted only after their migration-defined shape is
checked. A mismatch aborts the transaction; no existing data is modified.
"""
import re

import sqlalchemy as sa
from alembic import context, op


def _normal_default(value):
    if value is None:
        return None
    return str(value).split('::', 1)[0].strip().strip("'").lower()


def _column_matches(name, actual, expected, dialect):
    actual_type = str(actual['type'].compile(dialect=dialect)).upper()
    expected_type = str(expected.type.compile(dialect=dialect)).upper()
    if actual_type != expected_type or actual['nullable'] != expected.nullable:
        raise RuntimeError(f'Existing {name} has an incompatible type or nullability')
    if expected.server_default is not None:
        want = _normal_default(expected.server_default.arg)
        if _normal_default(actual.get('default')) != want:
            raise RuntimeError(f'Existing {name} has an incompatible default')


def ensure_table(name, *elements):
    if context.is_offline_mode():
        return op.create_table(name, *elements)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if not inspector.has_table(name):
        return op.create_table(name, *elements)
    expected = sa.Table(name, sa.MetaData(), *elements)
    actual = {column['name']: column for column in inspector.get_columns(name)}
    for column in expected.columns:
        if column.name not in actual:
            raise RuntimeError(f'Existing {name} is missing column {column.name}')
        _column_matches(f'{name}.{column.name}', actual[column.name], column, conn.dialect)
    if set(inspector.get_pk_constraint(name)['constrained_columns']) != {c.name for c in expected.primary_key.columns}:
        raise RuntimeError(f'Existing {name} has an incompatible primary key')
    foreign_keys = {(tuple(fk['constrained_columns']), fk['referred_table'], tuple(fk['referred_columns']),
                     (fk.get('options') or {}).get('ondelete', '').upper()) for fk in inspector.get_foreign_keys(name)}
    for column in expected.columns:
        for fk in column.foreign_keys:
            target_table, target_column = fk.target_fullname.rsplit('.', 1)
            if ((column.name,), target_table, (target_column,), (fk.ondelete or '').upper()) not in foreign_keys:
                raise RuntimeError(f'Existing {name}.{column.name} has an incompatible foreign key')
    unique_sets = {tuple(item['column_names']) for item in inspector.get_unique_constraints(name)}
    for constraint in expected.constraints:
        if isinstance(constraint, sa.UniqueConstraint) and tuple(c.name for c in constraint.columns) not in unique_sets:
            raise RuntimeError(f'Existing {name} is missing a required unique constraint')
    checks = {item['name']: item['sqltext'] for item in inspector.get_check_constraints(name)}
    for constraint in expected.constraints:
        if isinstance(constraint, sa.CheckConstraint):
            actual_check = checks.get(constraint.name)
            wanted_literals = set(re.findall(r"'([^']*)'", str(constraint.sqltext)))
            actual_literals = set(re.findall(r"'([^']*)'", actual_check or ''))
            column = re.match(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+IN\s*\(', str(constraint.sqltext), re.I)
            if (not actual_check or wanted_literals != actual_literals or not column
                    or not re.search(r'\b' + re.escape(column.group(1)) + r'\b', actual_check, re.I)
                    or re.search(r'\b(?:NOT|OR|AND)\b|<>|!=', actual_check, re.I)):
                raise RuntimeError(f'Existing {name} has an incompatible check {constraint.name}')


def ensure_column(table, column):
    if context.is_offline_mode():
        return op.add_column(table, column)
    conn = op.get_bind()
    actual = {item['name']: item for item in sa.inspect(conn).get_columns(table)}
    if column.name not in actual:
        return op.add_column(table, column)
    _column_matches(f'{table}.{column.name}', actual[column.name], column, conn.dialect)


def ensure_index(name, table, columns, *, unique=False):
    if context.is_offline_mode():
        return op.create_index(name, table, columns, unique=unique)
    indexes = {item['name']: item for item in sa.inspect(op.get_bind()).get_indexes(table)}
    existing = indexes.get(name)
    if existing is None:
        return op.create_index(name, table, columns, unique=unique)
    options = existing.get('dialect_options') or {}
    if (existing.get('column_names') != list(columns) or bool(existing.get('unique')) != unique
            or options.get('postgresql_where') is not None or options.get('sqlite_where') is not None):
        raise RuntimeError(f'Existing index {name} does not match the migration')
