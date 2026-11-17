"""
In-process runtime for the specialised report model.

A small GGUF model (the distilled BreachTrace reporter) run with llama.cpp
through `llama-cpp-python`, inside the backend process. No model server, no
GPU, no network. The same code works in Docker and in a native installer.

Footprint discipline, because this ships on users' laptops:
  * the model loads on first use, not at startup;
  * it unloads after REPORT_MODEL_IDLE_S seconds without a report, so an idle
    BreachTrace costs nothing;
  * output is constrained to the report JSON schema, so a small model cannot
    wander off-format and no tokens are wasted on prose we would discard.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any

import config
from reporter.prompt import SECTIONS_SCHEMA, build_messages, parse_sections

logger = logging.getLogger(__name__)

_MAX_TOKENS = 700


def gate_manifest_path(model_path: str) -> str:
    return model_path + ".gate.json"


_sha_cache: dict[tuple[str, float], str] = {}


def _file_sha256(path: str) -> str:
    """sha256 of the model file, cached per (path, mtime) — it is ~400 MB."""
    key = (path, os.path.getmtime(path))
    if key not in _sha_cache:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        _sha_cache[key] = digest.hexdigest()
    return _sha_cache[key]
_CONTEXT_TOKENS = 4096


class LocalReportModel:
    """Lazily-loaded, idle-unloaded llama.cpp model. Thread-safe."""

    def __init__(self, model_path: str, *, threads: int = 0, idle_seconds: int = 300) -> None:
        self.model_path = model_path
        self.threads = threads or max(1, (os.cpu_count() or 2) - 1)
        self.idle_seconds = idle_seconds
        self._llm: Any = None
        self._lock = threading.Lock()
        self._unload_timer: threading.Timer | None = None

    # ------------------------------------------------------------------
    @staticmethod
    def runtime_installed() -> bool:
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            return False
        return True

    def gate_passed(self) -> bool:
        """
        True when `<model>.gate.json` records a passing quality gate.

        An untuned or unevaluated model can pass the grounding validator and
        still write worse prose than the template (observed: a base 0.5B model
        turning one charge into "charges, refunds, and payouts"). So the model
        only runs once research/report_eval.py's Gemini-parity gate has passed
        for this exact file. REPORT_MODEL_REQUIRE_GATE=false bypasses this for
        research runs only.
        """
        if not config.REPORT_MODEL_REQUIRE_GATE:
            return True
        manifest = gate_manifest_path(self.model_path)
        try:
            with open(manifest, encoding="utf-8") as fh:
                gate = json.load(fh)
        except (OSError, ValueError):
            return False
        return gate.get("passed") is True and gate.get("model_sha256") == _file_sha256(self.model_path)

    def available(self) -> bool:
        if not (os.path.isfile(self.model_path) and self.runtime_installed()):
            return False
        if not self.gate_passed():
            logger.warning(
                "[REPORT MODEL] %s has no passing quality gate (%s); using the template writer",
                os.path.basename(self.model_path),
                gate_manifest_path(self.model_path),
            )
            return False
        return True

    def _load(self) -> Any:
        if self._llm is None:
            from llama_cpp import Llama

            started = time.monotonic()
            self._llm = Llama(
                model_path=self.model_path,
                n_ctx=_CONTEXT_TOKENS,
                n_threads=self.threads,
                n_gpu_layers=0,
                verbose=False,
            )
            logger.info(
                "[REPORT MODEL] Loaded %s in %.1fs",
                os.path.basename(self.model_path),
                time.monotonic() - started,
            )
        return self._llm

    def _schedule_unload(self) -> None:
        if self._unload_timer is not None:
            self._unload_timer.cancel()
        if self.idle_seconds > 0:
            self._unload_timer = threading.Timer(self.idle_seconds, self.unload)
            self._unload_timer.daemon = True
            self._unload_timer.start()

    def unload(self) -> None:
        with self._lock:
            if self._llm is not None:
                self._llm = None
                logger.info("[REPORT MODEL] Unloaded after %ss idle", self.idle_seconds)

    # ------------------------------------------------------------------
    def generate(self, facts: dict, feedback: list[str] | None = None) -> dict | None:
        """Report sections for ``facts``, or None when the output is unusable."""
        content = self.generate_json(build_messages(facts, feedback), SECTIONS_SCHEMA)
        return parse_sections(content) if content else None

    def generate_json(self, messages: list[dict], schema: dict, *, max_tokens: int = _MAX_TOKENS) -> str:
        """Generate schema-constrained JSON for another grounded local task."""
        with self._lock:
            llm = self._load()
            try:
                response = llm.create_chat_completion(
                    messages=messages,
                    response_format={"type": "json_object", "schema": schema},
                    temperature=0.2,
                    repeat_penalty=1.1,
                    max_tokens=max_tokens,
                )
            finally:
                self._schedule_unload()

        choice = response["choices"][0]
        if choice.get("finish_reason") == "length":
            logger.warning("[REPORT MODEL] JSON output hit the %d-token limit", max_tokens)
            return ""
        return choice["message"].get("content", "")


_instance: LocalReportModel | None = None


def get_local_model() -> LocalReportModel | None:
    """The configured model, or None when disabled or not installed."""
    global _instance
    if not config.REPORT_MODEL_ENABLED or not config.REPORT_MODEL_PATH:
        return None
    if _instance is None or _instance.model_path != config.REPORT_MODEL_PATH:
        _instance = LocalReportModel(
            config.REPORT_MODEL_PATH,
            threads=config.REPORT_MODEL_THREADS,
            idle_seconds=config.REPORT_MODEL_IDLE_S,
        )
    return _instance if _instance.available() else None
