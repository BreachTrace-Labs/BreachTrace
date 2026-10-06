"""
Shared pytest setup.

`db/database.py` builds a SQLAlchemy engine at import time from
`config.DATABASE_URL`. Any test that imports a router therefore fails at
collection with "Could not parse SQLAlchemy URL" unless a URL is set — even
though no test touches a real database.

Setting a throwaway SQLite URL here keeps the suite runnable with no services
and no credentials, which is what makes it usable in CI. `create_engine()` does
not connect eagerly, so nothing is created and nothing is written.

This must run before test modules are imported. pytest loads conftest.py first,
so assigning to os.environ at module scope is early enough.
"""

import os

# Only fill in a default — never clobber a real DATABASE_URL, so the same suite
# can be pointed at a live database deliberately.
os.environ.setdefault("DATABASE_URL", "sqlite://")

# The collectors read these at construction time. Empty strings would make
# StripeEventsCollector/TwilioUsageCollector raise ValueError in tests that only
# exercise field mapping, so give them obviously fake values.
os.environ.setdefault("STRIPE_API_KEY", "sk_test_dummy_for_tests")
os.environ.setdefault("TWILIO_ACCOUNT_SID", "ACdummyfortests00000000000000000")
os.environ.setdefault("TWILIO_AUTH_TOKEN", "dummy_token_for_tests")

# Reports and search must be deterministic and offline in tests: no embedding
# model download, no local report model, no Gemini call even when the
# developer's .env holds a key. Tests that exercise those paths inject fakes.
os.environ["EMBED_ENABLED"] = "false"
os.environ["REPORT_MODEL_ENABLED"] = "false"
os.environ["REPORT_PROVIDER"] = "none"


import pytest  # noqa: E402


@pytest.fixture
def sqlite_factory():
    """
    Session factory over a fresh in-memory SQLite database with the full schema.

    JSONB columns are Postgres-only, so they compile as JSON here. Used by tests
    that need real persistence (pipeline, search index) without a server.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    @compiles(JSONB, "sqlite")
    def _jsonb_as_json(_type, _compiler, **_kw):
        return "JSON"

    from db.models import Base
    from rag.index import reset_kb_state

    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    reset_kb_state()
    yield sessionmaker(bind=engine, expire_on_commit=False)
    reset_kb_state()
