from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from db.crud import create_incident, reset_incident_for_refresh
from db.models import ForensicEvent
from routers.incidents import StripeRequestLogIn, add_stripe_request_log


def _incident(db, hint="rk_test_****1234"):
    return create_incident(db, credential_type="stripe_secret_key", credential_hint=hint,
                           access_key_id=None, repo_url="https://example.invalid/repo",
                           commit_hash="abc", exposure_start=datetime.now(timezone.utc) - timedelta(minutes=5))


def _record(**overrides):
    data = dict(created_at=int(datetime.now(timezone.utc).timestamp()), livemode=False,
                method="GET", request_id="req_Test123", status=200,
                url="/v1/customers/cus_private?secret=private", account_confirmed=True)
    data.update(overrides)
    return StripeRequestLogIn(**data)


def test_sandbox_request_is_redacted_deduplicated_and_survives_refresh(sqlite_factory):
    with sqlite_factory() as db:
        incident = _incident(db)
        assert add_stripe_request_log(incident.incident_id, _record(), db) == {"status": "added"}
        assert add_stripe_request_log(incident.incident_id, _record(), db) == {"status": "duplicate"}
        reset_incident_for_refresh(db, incident.incident_id)
        rows = db.query(ForensicEvent).all()
        assert len(rows) == 1
        assert rows[0].api_action == "GET /v1/customers/…"
        assert "private" not in str(rows[0].raw_data)
        assert rows[0].raw_data["attribution"] == "sandbox activity; key identity not provided"


def test_rejects_wrong_mode_unconfirmed_and_outside_window(sqlite_factory):
    with sqlite_factory() as db:
        incident = _incident(db)
        for record in (_record(livemode=True), _record(account_confirmed=False),
                       _record(created_at=int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()))):
            with pytest.raises(HTTPException):
                add_stripe_request_log(incident.incident_id, record, db)
        live_incident = _incident(db, hint="sk_live_****1234")
        with pytest.raises(HTTPException):
            add_stripe_request_log(live_incident.incident_id, _record(), db)
        assert db.query(ForensicEvent).count() == 0
