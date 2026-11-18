"""
Report writers and the validated upgrade path.

Every incident first gets the deterministic template report (compose.py). A
writer may then *upgrade* the prose. An upgrade is accepted only if it passes
the grounding validator, on the first attempt or on one retry that is told what
it got wrong; otherwise the template report stands. A model can therefore make
a report more readable, never less accurate.

Writers, all speaking the one contract in reporter/prompt.py:
  * local  — the distilled in-process model (the shipped default);
  * gemini — optional cloud writer: interim provider until the local model
             passes its quality gate, and the teacher for distillation.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

import config
from reporter.compose import render_report
from reporter.local_model import get_local_model
from reporter.prompt import SECTIONS_SCHEMA, SYSTEM_PROMPT, build_messages, parse_sections
from reporter.validate import validate_sections

logger = logging.getLogger(__name__)

Writer = Callable[[dict, "list[str] | None"], "dict | None"]
_selected_local = None
_local_lock = threading.Lock()


def local_writer() -> Writer | None:
    model = get_local_model()
    return model.generate if model else None


# Gemini's response_schema is an OpenAPI subset: it rejects JSON-Schema keys
# such as additionalProperties, which llama.cpp's grammar mode accepts.
_GEMINI_UNSUPPORTED_KEYS = ("additionalProperties", "minItems", "maxItems")


def _gemini_schema(schema: dict) -> dict:
    return {
        key: _gemini_schema(value) if isinstance(value, dict) else value
        for key, value in schema.items()
        if key not in _GEMINI_UNSUPPORTED_KEYS
    }


def gemini_writer(model_name: str | None = None) -> Writer | None:
    """
    Gemini through the supported `google-genai` SDK, or None if unavailable.

    The deprecated `google.generativeai` package is no longer used here.
    """
    if not config.GEMINI_API_KEY:
        return None
    try:
        from google import genai
    except ImportError:
        logger.info("google-genai not installed — Gemini writer unavailable")
        return None

    client = genai.Client(api_key=config.GEMINI_API_KEY)
    name = model_name or config.GEMINI_REPORT_MODEL

    def write(facts: dict, feedback: list[str] | None = None) -> dict | None:
        messages = build_messages(facts, feedback)
        response = client.models.generate_content(
            model=name,
            contents=messages[1]["content"],
            config={
                "system_instruction": SYSTEM_PROMPT,
                "response_mime_type": "application/json",
                "response_schema": _gemini_schema(SECTIONS_SCHEMA),
                "temperature": 0.3,
            },
        )
        return parse_sections(getattr(response, "text", "") or "")

    return write


def _writers() -> list[tuple[str, Writer]]:
    global _selected_local
    import model_settings
    from llm_client import generate
    settings = model_settings.current()
    if settings.provider == "none":
        return []
    if settings.provider == "local":
        from reporter.local_model import LocalReportModel
        with _local_lock:
            if _selected_local is None or _selected_local.model_path != settings.model_path:
                if _selected_local is not None:
                    _selected_local.unload()
                _selected_local = LocalReportModel(settings.model_path, threads=config.REPORT_MODEL_THREADS,
                                                   idle_seconds=config.REPORT_MODEL_IDLE_S)
            model = _selected_local
            return [("local_model", model.generate)] if model.available() else []

    def write(facts: dict, feedback: list[str] | None = None) -> dict | None:
        return parse_sections(generate(settings, build_messages(facts, feedback), json_output=True))

    return [(settings.provider, write)]


def write_validated(writer: Writer, facts: dict) -> tuple[dict | None, list[str]]:
    """One attempt plus one corrective retry. Returns (sections, last violations)."""
    violations: list[str] = ["output was not valid report JSON"]
    feedback: list[str] | None = None
    for _ in range(2):
        sections = writer(facts, feedback)
        if sections is None:
            violations = ["output was not valid report JSON"]
        else:
            violations = validate_sections(sections, facts)
            if not violations:
                return sections, []
        feedback = violations
    return None, violations


def upgrade_report(facts: dict) -> tuple[str, str] | None:
    """
    (report_text, report_source) from the first writer whose output validates,
    or None when no writer is available or none produced grounded prose.
    """
    # The current prose validator cannot reliably prove that a model has kept
    # failed GCP attempts separate from completed operations. Keep the
    # outcome-aware template until that distinction can be validated.
    if facts.get('platform') == 'gcp' and facts.get('failed_count', 0):
        logger.info('Keeping deterministic report for GCP events with failures')
        return None
    for name, writer in _writers():
        try:
            sections, violations = write_validated(writer, facts)
        except Exception:
            logger.exception("[REPORT] %s writer failed", name)
            continue
        if sections is not None:
            return render_report(facts, sections), name
        logger.warning("[REPORT] %s output rejected: %s", name, "; ".join(violations[:3]))
    return None
