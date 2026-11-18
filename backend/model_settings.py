"""Explicit BYOM selection; persist preferences, keep entered secrets in memory."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, model_validator

import config


class ModelSettings(BaseModel):
    provider: Literal["none", "openai", "anthropic", "ollama", "local", "gemini", "groq"] = "none"
    model: str = Field("", max_length=200, pattern=r"^[^\r\n]*$")
    answer_model: str = Field("", max_length=200, pattern=r"^[^\r\n]*$")
    offline_models_only: bool = False
    ollama_url: str = "http://127.0.0.1:11434"
    model_path: str = Field("", max_length=1000)
    timeout_s: int = Field(60, ge=5, le=300)
    # SecretStr prevents accidental repr/log disclosure; never persisted/returned.
    api_key: SecretStr | None = Field(None, exclude=True)
    clear_api_key: bool = Field(False, exclude=True)

    @model_validator(mode="after")
    def validate_selection(self):
        if self.offline_models_only and self.provider in {"openai", "anthropic", "gemini", "groq"}:
            raise ValueError("Offline model mode requires a local or deterministic provider")
        if self.provider in {"openai", "anthropic", "ollama", "gemini", "groq"} and not self.model.strip():
            raise ValueError("Choose a model name for this provider")
        if self.provider == "local" and not self.model_path.strip():
            raise ValueError("Choose an existing GGUF model file")
        url = urlsplit(self.ollama_url)
        if (url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1", "::1"}
                or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}):
            raise ValueError("Ollama URL must be a local HTTP origin")
        try:
            port = url.port
        except ValueError:
            raise ValueError("Invalid Ollama port") from None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid Ollama port")
        self.ollama_url = self.ollama_url.rstrip("/")
        return self


_lock = threading.RLock()
_state: ModelSettings | None = None
_secret: str | None = None


def settings_path() -> Path:
    return Path(os.getenv("MODEL_SETTINGS_FILE", str(Path(__file__).resolve().parents[1] / "data" / "model-settings.json")))


def current() -> ModelSettings:
    global _state
    with _lock:
        if _state is None:
            path = settings_path()
            if path.exists():
                _state = ModelSettings.model_validate_json(path.read_text())
            else:
                # Legacy installations can opt in using their existing env settings.
                provider = config.REPORT_PROVIDER
                if provider == "local":
                    _state = ModelSettings(provider="local", model_path=config.REPORT_MODEL_PATH)
                elif provider == "gemini":
                    _state = ModelSettings(provider="gemini", model=config.GEMINI_REPORT_MODEL)
                else:
                    _state = ModelSettings()
        return _state.model_copy(deep=True)


def key_for(settings: ModelSettings) -> str:
    with _lock:
        if _secret and current().provider == settings.provider:
            return _secret
    env = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY", "groq": "GROQ_API_KEY"}
    return os.getenv(env.get(settings.provider, ""), "")


def save(settings: ModelSettings) -> dict:
    global _state, _secret
    with _lock:
        previous = current()
        secret = _secret if previous.provider == settings.provider else None
        if settings.clear_api_key:
            secret = None
        elif settings.api_key and settings.api_key.get_secret_value().strip():
            secret = settings.api_key.get_secret_value().strip()
        path = settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(settings.model_dump(), stream, indent=2)
        temporary.replace(path)
        _state = ModelSettings.model_validate(settings.model_dump())
        _secret = secret
        return public()


def public() -> dict:
    settings = current()
    return {**settings.model_dump(), "api_key_configured": bool(key_for(settings)),
            "api_key_persistence": "memory-only; environment variables also supported"}
