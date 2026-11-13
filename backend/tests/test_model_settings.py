import json
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import model_settings as models
from llm_client import generate
from routers.settings import router


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_SETTINGS_FILE", str(tmp_path / "settings.json"))
    monkeypatch.setattr(models, "_state", None)
    monkeypatch.setattr(models, "_secret", None)
    monkeypatch.setattr(models.config, "REPORT_PROVIDER", "none")
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def test_secrets_never_persist_or_return_and_provider_changes_clear_them():
    secret = "synthetic-only-token"
    result = models.save(models.ModelSettings(provider="openai", model="chosen-model", api_key=secret))
    assert result["api_key_configured"]
    assert secret not in json.dumps(result)
    assert secret not in models.settings_path().read_text()
    assert models.key_for(models.current()) == secret
    models.save(models.ModelSettings(provider="anthropic", model="chosen-model"))
    assert models.key_for(models.current()) == ""


def test_no_model_by_default_and_settings_survive_reload():
    assert models.current().provider == "none"
    models.save(models.ModelSettings(provider="ollama", model="installed-model"))
    models._state = None
    assert models.current().model == "installed-model"


@pytest.mark.parametrize("url", ["http://evil.test", "http://127.0.0.1@evil.test", "https://localhost", "http://localhost/path", "http://localhost:99999"])
def test_ollama_cannot_be_used_as_arbitrary_proxy(url):
    with pytest.raises(ValueError):
        models.ModelSettings(ollama_url=url)


def test_settings_api_local_only_and_no_cross_origin_requests():
    app = FastAPI(); app.include_router(router)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 5000)) as local:
        assert local.get("/settings/model").status_code == 200
        assert local.put("/settings/model", json={"provider": "none"}, headers={"origin": "https://evil.test"}).status_code == 403
    with TestClient(app, base_url="http://localhost", client=("203.0.113.1", 5000)) as remote:
        assert remote.get("/settings/model").status_code == 403


@pytest.mark.parametrize("provider,data,expected_path", [
    ("openai", {"output": [{"content": [{"type": "output_text", "text": "OK"}]}]}, "/responses"),
    ("anthropic", {"content": [{"type": "text", "text": "OK"}]}, "/messages"),
    ("ollama", {"message": {"content": "OK"}}, "/api/chat"),
])
def test_provider_contracts(monkeypatch, provider, data, expected_path):
    settings = models.ModelSettings(provider=provider, model="user-chosen-model", api_key="synthetic-token")
    models.save(settings)
    response = Mock(status_code=200); response.json.return_value = data
    post = Mock(return_value=response); monkeypatch.setattr("llm_client.requests.post", post)
    assert generate(models.current(), [{"role": "system", "content": "Rules"}, {"role": "user", "content": "JSON please"}], json_output=True) == "OK"
    args, kwargs = post.call_args
    assert args[0].endswith(expected_path)
    assert kwargs["json"]["model"] == "user-chosen-model"
    assert kwargs["allow_redirects"] is False
    if provider == "openai":
        assert kwargs["json"]["store"] is False
    if provider == "anthropic":
        assert kwargs["json"]["system"] == "Rules"


def test_upstream_errors_do_not_echo_secrets(monkeypatch):
    models.save(models.ModelSettings(provider="openai", model="selected", api_key="synthetic-token"))
    monkeypatch.setattr("llm_client.requests.post", Mock(return_value=Mock(status_code=401)))
    with pytest.raises(ValueError, match="HTTP 401"):
        generate(models.current(), [])


def test_report_writer_uses_selected_model_and_preserves_grounding(monkeypatch):
    from reporter import writers
    models.save(models.ModelSettings(provider="ollama", model="my-local-model"))
    monkeypatch.setattr("llm_client.generate", lambda *a, **kw: '{"executive_summary":"fiction", "narrative":["fiction"], "business_impact":"fiction"}')
    assert writers._writers()[0][0] == "ollama"
    models.save(models.ModelSettings())
    assert writers._writers() == []


def test_validation_errors_do_not_echo_submitted_key(monkeypatch):
    import config
    monkeypatch.setattr(config, "validate_config", lambda: None)
    from main import validation_error
    from fastapi.exceptions import RequestValidationError
    app = FastAPI(); app.include_router(router)
    app.add_exception_handler(RequestValidationError, validation_error)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 1234)) as client:
        response = client.put("/settings/model", json={"provider": "openai", "model": "", "api_key": "synthetic-private-key"})
        assert response.status_code == 422
        assert "synthetic-private-key" not in response.text
