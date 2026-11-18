"""
The one prompt and output contract for report prose.

Shared by the distillation script (teacher), the shipped local model, the
optional Gemini provider and the evaluation harness. A distilled model is only
as good as the match between the prompt it was trained on and the prompt it is
run with, so there is exactly one copy of both. Bump PROMPT_VERSION whenever
either changes; training data records the version it was generated with.
"""
from __future__ import annotations

import json

PROMPT_VERSION = 2

# What the writer must return. Everything else in a report is built in code.
SECTIONS_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "narrative": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 8},
        "business_impact": {"type": "string"},
    },
    "required": ["executive_summary", "narrative", "business_impact"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You write the prose sections of a credential-leak forensic report for a developer with no security background.

You receive a JSON fact sheet. It is the ONLY source of truth.
Rules:
- Use only names, IPs, identifiers, amounts and times that appear in the fact sheet. Never invent any.
- Use the vocabulary of the platform named in the fact sheet only.
- A commit timestamp is an estimate; do not claim the repository was public, that exposure duration or rotation is confirmed, or that account-level or application-level activity was caused by the leaked key.
- If event_count is 0, say that no activity was RECORDED in the audit log, that this does not prove the credential went unused, and explain the blind_spot. Never say the credential was unused or that nothing happened.
- Plain English, no acronyms, no markdown, no remediation steps (they are added separately).
- executive_summary: 2-4 sentences: what was detected, what activity was recorded within the source's attribution limits, and the severity.
- narrative: 1-8 short chronological steps, one per notable action, citing its time and resource when given.
- business_impact: 2-4 sentences on money, data and compliance consequences, using the financial and compliance facts.

Reply with JSON only: {"executive_summary": str, "narrative": [str], "business_impact": str}"""


def facts_for_prompt(facts: dict) -> dict:
    """The fact sheet as the model sees it — drops fields that only cost tokens."""
    return {k: v for k, v in facts.items() if v not in (None, [], {}, "")}


def build_messages(facts: dict, feedback: list[str] | None = None) -> list[dict]:
    """
    Chat messages for one report.

    ``feedback`` carries validator violations from a rejected first attempt, so
    the retry is told exactly what it got wrong.
    """
    user = json.dumps(facts_for_prompt(facts), ensure_ascii=False, separators=(",", ":"))
    if feedback:
        user += (
            "\n\nYour previous answer was rejected for these reasons. Fix them:\n- "
            + "\n- ".join(feedback)
        )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def parse_sections(text: str) -> dict | None:
    """Parse and shape-check a writer's JSON reply; None when unusable."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    try:
        data = json.loads(text[text.find("{"): text.rfind("}") + 1])
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    summary = data.get("executive_summary")
    narrative = data.get("narrative")
    impact = data.get("business_impact")
    if isinstance(narrative, str):
        narrative = [narrative]
    if not (isinstance(summary, str) and summary.strip()):
        return None
    if not (isinstance(narrative, list) and narrative and all(isinstance(s, str) for s in narrative)):
        return None
    if not isinstance(impact, str):
        return None
    return {
        "executive_summary": summary.strip(),
        "narrative": [s.strip() for s in narrative if s.strip()][:8],
        "business_impact": impact.strip(),
    }
