"""Gemini-based incident report generator."""

from __future__ import annotations

import logging
from typing import Iterable

import google.generativeai as genai

import config
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

_model: genai.GenerativeModel | None = None


def _get_model() -> genai.GenerativeModel:
    """Return the Gemini model, initialising it on first use."""
    global _model
    if _model is None:
        genai.configure(api_key=config.GEMINI_API_KEY)
        _model = genai.GenerativeModel("gemini-2.5-flash")
    return _model


def _format_event_line(event: ForensicEvent) -> str:
    src = event.event_source or "unknown-source"
    ip = event.source_ip or "unknown-ip"
    resource = event.affected_resource or "unspecified-resource"
    category = event.impact_category or "unclassified"
    ts = event.timestamp.isoformat()
    return f"{ts} — {event.api_action} from {ip} on {resource} via {src} (category: {category})"


def _build_prompt(
    *,
    events: Iterable[ForensicEvent],
    overall_severity: str,
    exposure_duration_seconds: int,
    affected_resources: list[str],
    source_ips: list[str],
) -> str:
    event_lines = ["- " + _format_event_line(e) for e in events]
    events_block = "\n".join(event_lines) if event_lines else "- No CloudTrail events were captured."

    stats = [
        f"Overall severity: {overall_severity or 'UNKNOWN'}",
        f"Exposure duration: {exposure_duration_seconds}s",
        f"Unique affected resources: {', '.join(affected_resources) if affected_resources else 'none recorded'}",
        f"Source IPs observed: {', '.join(source_ips) if source_ips else 'none recorded'}",
    ]

    return f"""
You are a forensic incident responder. The audience is a developer with no security background. Avoid acronyms.
Keep the entire report under 400 words. Use exact resource names provided.

Generate a forensic incident report in four sections:
1) Executive Summary — 1 paragraph, plain English, no jargon.
2) Chronological Narrative — what the attacker did step by step.
3) Business Impact Assessment.
4) Remediation Checklist — number each item, start with ☐, be specific and include exact resource names.

Context:
- {stats[0]}
- {stats[1]}
- {stats[2]}
- {stats[3]}

Events:
{events_block}
"""


def generate_report(
    events: list[ForensicEvent],
    overall_severity: str,
    exposure_duration_seconds: int,
    affected_resources: list[str],
    source_ips: list[str],
) -> str:
    """
    Call Gemini API to generate a plain-English forensic incident report.

    Fallback: returns a minimal text summary when Gemini fails or no key is set.
    """
    prompt = _build_prompt(
        events=events,
        overall_severity=overall_severity,
        exposure_duration_seconds=exposure_duration_seconds,
        affected_resources=affected_resources,
        source_ips=source_ips,
    )

    if not config.GEMINI_API_KEY:
        return (
            "Gemini not configured — fallback summary\n\n"
            + prompt.replace("Generate a forensic incident report in four sections:", "Context")
        )

    try:
        response = _get_model().generate_content(prompt)
        text = getattr(response, "text", None) or "".join(getattr(response, "candidates", []))
        if text:
            return text.strip()
    except Exception:
        # Best-effort resilience — never block the pipeline on LLM failure.
        logger.exception("Gemini generation failed")
        pass

    # Fallback if Gemini is unavailable
    fallback_lines = [
        "Gemini report unavailable — using auto-generated summary.",
        f"Severity: {overall_severity or 'UNKNOWN'}",
        f"Duration: {exposure_duration_seconds}s",
        f"Events counted: {len(events)}",
        "Remediation checklist:",
        "1) Rotate the exposed credential and revoke active keys.",
        "2) Audit CloudTrail for further suspicious calls during the window.",
        "3) Patch or remove the leaking secret from version control history.",
    ]
    return "\n".join(fallback_lines)
