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
