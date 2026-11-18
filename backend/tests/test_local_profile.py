import pytest

import config


def test_local_profile_starts_without_cloud_credentials(monkeypatch):
    for key in config.REQUIRED_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://local/test")
    monkeypatch.setenv("BREACHTRACE_LOCAL_TEST_MODE", "true")
    config.validate_config()


def test_standard_profile_keeps_existing_validation(monkeypatch):
    monkeypatch.delenv("BREACHTRACE_LOCAL_TEST_MODE", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    with pytest.raises(SystemExit):
        config.validate_config()


def test_bootstrap_refuses_other_database(monkeypatch):
    from scripts import local_dev
    monkeypatch.setattr(local_dev, "load_profile", lambda: None)
    monkeypatch.setenv("DATABASE_URL", "postgresql://someone@127.0.0.1:5432/production")
    with pytest.raises(SystemExit, match="Refusing schema setup"):
        local_dev.bootstrap()


def test_local_index_upgrade_preserves_rows_and_rejects_multiple_organisations():
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import IntegrityError
    from scripts.local_dev import ensure_local_organisation_index

    engine = create_engine('sqlite://')
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE organisations (id TEXT PRIMARY KEY)'))
        connection.execute(text("INSERT INTO organisations (id) VALUES ('existing')"))
    ensure_local_organisation_index(engine)
    ensure_local_organisation_index(engine)
    with engine.begin() as connection:
        assert connection.execute(text('SELECT COUNT(*) FROM organisations')).scalar_one() == 1
        with pytest.raises(IntegrityError):
            connection.execute(text("INSERT INTO organisations (id) VALUES ('other')"))

    other = create_engine('sqlite://')
    with other.begin() as connection:
        connection.execute(text('CREATE TABLE organisations (id TEXT PRIMARY KEY)'))
        connection.execute(text("INSERT INTO organisations (id) VALUES ('one'), ('two')"))
    with pytest.raises(SystemExit, match='multiple organisations'):
        ensure_local_organisation_index(other)
    with other.connect() as connection:
        assert connection.execute(text('SELECT COUNT(*) FROM organisations')).scalar_one() == 2
