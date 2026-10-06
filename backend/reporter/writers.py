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
from typing import Callable

import config
from reporter.compose import render_report
from reporter.local_model import get_local_model
from reporter.prompt import SECTIONS_SCHEMA, SYSTEM_PROMPT, build_messages, parse_sections
from reporter.validate import validate_sections

logger = logging.getLogger(__name__)

Writer = Callable[[dict, "list[str] | None"], "dict | None"]


def local_writer() -> Writer | None:
    model = get_local_model()
    return model.generate if model else None


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
                "response_schema": SECTIONS_SCHEMA,
                "temperature": 0.3,
            },
        )
        return parse_sections(getattr(response, "text", "") or "")

    return write


def _writers() -> list[tuple[str, Writer]]:
    provider = config.REPORT_PROVIDER
    candidates: list[tuple[str, Callable[[], Writer | None]]] = []
    if provider in ("auto", "local"):
        candidates.append(("local_model", local_writer))
    if provider in ("auto", "gemini"):
        candidates.append(("gemini", gemini_writer))

    writers = []
    for name, factory in candidates:
        writer = factory()
        if writer is not None:
            writers.append((name, writer))
    return writers


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
