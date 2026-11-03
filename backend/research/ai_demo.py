"""Synthetic AI incidents for UI previews. No provider calls or real keys."""
import base64
from datetime import datetime
import json
import random
import string
from uuid import NAMESPACE_URL, uuid5

from detector.ai_keys import RULES
from detector.scanner import scan_text


def _sources():
    def body(provider, length):
        rng = random.Random("breachtrace-ui-demo-v1-" + provider)
        return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(length))

    values = {
        "openai": "sk-proj-" + body("openai", 90),
        "anthropic": "sk-ant-api03-" + body("anthropic", 93) + "AA",
        "gemini": "AIza" + body("gemini", 35),
        "deepseek": "sk-" + body("deepseek", 32),
        "sarvam": "sk_" + body("sarvam", 48),
        "groq": "gsk_" + body("groq", 52),
    }
    for provider, value in values.items():
        if provider == "anthropic":
            encoded = "".join(f"\\u{ord(char):04x}" for char in value)
            source = f'ANTHROPIC_API_KEY="{encoded}"'
        elif provider == "deepseek":
            source = f'DEEPSEEK_API_KEY_HEX="{value.encode().hex()}"'
        elif provider == "sarvam":
            source = f'SARVAM_API_KEY_B64="{base64.b64encode(value.encode()).decode()}"'
        elif provider == "groq":
            source = f'GROQ_API_KEY="{value[:28]}" + "{value[28:]}"'
        else:
            source = f'{provider.upper()}_API_KEY="{value}"'
        yield provider, value, source


def demo_incidents():
    """Run the real detector, then return only masked presentation fixtures."""
    labels = {rule.provider: rule.label for rule in RULES}
    fixtures = []
    methods = {"plaintext": "Plaintext literal", "literal-escapes": "Unicode escapes",
               "hex": "Hexadecimal decoding", "base64": "Base64 decoding",
               "literal-concatenation": "Split string reconstruction"}
    for provider, value, source in _sources():
        matches = scan_text("# SYNTHETIC UI DEMO — fabricated credential\n" + source)
        assert len(matches) == 1 and matches[0].platform == provider
        match = matches[0]
        method = methods.get(match.detection_method, match.detection_method)
        reason = (f"Synthetic {labels[provider]} example detected using {method.lower()} "
                  f"({match.confidence} confidence). BreachTrace detects this credential type "
                  "but does not collect its usage. This fabricated key has not been validated "
                  "and represents no real provider activity.")
        fixtures.append({
            "incident_id": str(uuid5(NAMESPACE_URL, "breachtrace-ui-ai-demo-v1/" + provider)),
            "platform": provider, "credential_type": match.credential_type,
            "credential_hint": match.credential_hint,
            "access_key_id": None, "principal_id": None, "gcp_project_id": None,
            "azure_tenant_id": None, "azure_subscription_id": None,
            "repo_url": "local-test://synthetic-ai-demo/" + provider,
            "commit_hash": "synthetic-ai-demo-v1",
            "exposure_start": "2026-11-03T18:25:00Z", "exposure_end": None,
            "status": "complete", "forensic_tier": 2, "events": [],
            "overall_severity": None, "gdpr_flag": False,
            "unavailable_reason": reason, "report_source": "deterministic",
            "estimated_financial_impact": None,
            "report_text": (
                f"## Synthetic AI credential detection\n\n"
                f"**UI demonstration only. No valid key or real breach is represented.**\n\n"
                f"Provider: **{labels[provider]}**\n\n"
                f"Masked candidate: `{match.credential_hint}`\n\n"
                f"Recovery method: **{method}**. Pattern confidence: **{match.confidence}**.\n\n"
                f"Source: demo configuration, line {match.line_number}.\n\n"
                "## What this result means\n\n"
                "The real offline detector matched a deliberately fabricated source sample. "
                "Confidence describes the pattern match, not key validity. "
                "No key was sent to a provider. Usage, spend and compromise were not assessed.\n\n"
                "## For a real exposure\n\n"
                "Revoke the affected key, update deployments and review available provider "
                "usage and billing records. These demo rows are not research measurements."
            ),
            "remediation_steps": [
                "Demo only: no live credential needs rotation for this fabricated example.",
                "For a real leak, revoke the affected key in the provider console.",
                "Replace it in affected deployments and remove it from repository content/history.",
                "Review available usage and billing records; detection alone does not establish misuse.",
            ],
        })
        assert value not in json.dumps(fixtures[-1]) and source not in json.dumps(fixtures[-1])
    return fixtures


def seed_incidents(db):
    """Idempotently insert only the six specifically named demo fixtures."""
    from db.models import IncidentRecord
    fixtures = demo_incidents()
    for fixture in fixtures:
        row = db.get(IncidentRecord, fixture["incident_id"])
        if row is not None and row.repo_url != fixture["repo_url"]:
            raise ValueError("Demo ID conflicts with an existing non-demo incident")
        if row is None:
            row = IncidentRecord(incident_id=fixture["incident_id"])
            db.add(row)
        for name, value in fixture.items():
            if name in {"incident_id", "platform", "events", "estimated_financial_impact"}:
                continue
            if name == "exposure_start":
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            setattr(row, name, value)
    db.commit()
    return fixtures
