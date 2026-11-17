"""Simulation errors must not disclose caller-supplied credentials or source."""
import asyncio
from unittest.mock import Mock

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
import pytest

from db.database import get_db
from routers import simulate


def test_unmatched_credential_is_not_echoed_in_api_error():
    value = "gsk_" + ("Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU" * 2)[:52]
    forced = "synthetic-private-credential-do-not-echo"
    body = simulate.SimulateRequest(diff_text="+GROQ_API_KEY=" + value, credential=forced)
    db = Mock()
    with pytest.raises(HTTPException) as caught:
        asyncio.run(simulate.simulate(body, BackgroundTasks(), db))
    assert caught.value.status_code == 422
    assert forced not in caught.value.detail and value not in caught.value.detail
    db.add.assert_not_called()


def test_excessive_diff_is_rejected_before_scanning_without_echo(monkeypatch):
    import config
    monkeypatch.setattr(config, "validate_config", lambda: None)
    from main import validation_error
    app = FastAPI()
    app.include_router(simulate.router)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.dependency_overrides[get_db] = lambda: Mock()
    app.dependency_overrides[simulate.require_admin_or_lead] = lambda: Mock()
    scan = Mock(side_effect=AssertionError("Oversized source must not be scanned"))
    monkeypatch.setattr(simulate, "scan", scan)
    with TestClient(app) as client:
        response = client.post("/test/simulate", json={"diff_text": "synthetic-private-source-" + "x" * (2 * 1024 * 1024)})
    assert response.status_code == 422 and "synthetic-private-source" not in response.text
    scan.assert_not_called()
