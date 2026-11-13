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
