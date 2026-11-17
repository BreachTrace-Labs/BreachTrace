"""Validate the revision graph without connecting to any database."""
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_migrations_have_one_connected_head_and_no_missing_revisions():
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["f2b31ad59101"]
    revisions = list(scripts.walk_revisions())
    assert revisions[-1].down_revision is None
    assert "37cd4df9188c" in {revision.revision for revision in revisions}
