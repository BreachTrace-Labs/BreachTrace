"""Local operator model settings. Remote access needs an authenticated admin layer."""
from __future__ import annotations

import os
import platform
import subprocess
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request

import model_settings
from llm_client import generate


def local_operator(request: Request):
    allowed = {"localhost", "127.0.0.1", "::1"}
    if not request.client or request.client.host not in allowed or request.url.hostname not in allowed:
        raise HTTPException(403, "Model settings require a local operator connection")
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).hostname not in allowed:
        raise HTTPException(403, "Untrusted settings origin")


router = APIRouter(prefix="/settings/model", tags=["settings"], dependencies=[Depends(local_operator)])


@router.get("")
def get_settings():
    return model_settings.public()


@router.put("")
def put_settings(body: model_settings.ModelSettings):
    return model_settings.save(body)


@router.post("/test")
def test_model():
    settings = model_settings.current()
    try:
        if settings.provider == "none":
            return {"ok": True, "message": "Deterministic reports selected; no model required"}
        if settings.provider == "local":
            from reporter.local_model import LocalReportModel
            if not LocalReportModel(settings.model_path).available():
                raise ValueError("Local GGUF runtime, model, or quality gate unavailable")
        else:
            text = generate(settings, [{"role": "user", "content": "Reply with OK."}])
            if not text.strip():
                raise ValueError("The model returned no text")
            if settings.provider == 'ollama' and settings.answer_model.strip() and settings.answer_model.strip() != settings.model:
                answer_settings = settings.model_copy(update={'model': settings.answer_model.strip()})
                if not generate(answer_settings, [{"role": "user", "content": "Reply with OK."}]).strip():
                    raise ValueError("The answer model returned no text")
        return {"ok": True, "message": "Selected model is available"}
    except Exception:
        raise HTTPException(502, "Model check failed. Check credentials, model name, runtime and provider access.") from None


@router.get("/hardware")
def hardware():
    try:
        import psutil
        ram = round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except ImportError:
        try:
            if platform.system() == "Darwin":
                memory = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip())
            else:
                memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
            ram = round(memory / 1024 ** 3, 1)
        except (OSError, ValueError, subprocess.CalledProcessError):
            ram = None
    return {"os": platform.system(), "architecture": platform.machine(),
            "cpu_count": os.cpu_count(), "ram_gb": ram,
            "guidance": "Use an installed quantized local model that fits available memory. Benchmark on this hardware before choosing; no model is downloaded automatically."}
