"""
Assemble the final report markdown.

The same layout is used whoever writes the prose, so the dashboard, the
remediation parser and the knowledge-base index never have to care which
writer ran:

    ## Executive Summary      <- writer
    ## What Happened          <- writer (bullets)
    ## Business Impact        <- writer
    ## Remediation Checklist  <- code (reporter.remediation), always

`deterministic_sections()` is the template writer. It runs on every incident
first, so a report exists within the pipeline's 60-second target even on a
machine with no model at all.
"""
from __future__ import annotations

from reporter.facts import CATEGORY_LABELS
from reporter.remediation import build_remediation


_CREDENTIAL_NAMES = {
    "aws_access_key": "access key",
    "gcp_service_account": "service account key",
    "firebase_service_account": "Firebase service account key",
    "azure_service_principal": "service principal",
    "azure_client_secret": "client secret",
    "azure_storage_connection": "storage connection string",
    "stripe_secret_key": "secret API key",
    "twilio_account_sid": "account credential",
}


def _what(facts: dict) -> str:
    """'An AWS access key (AKIA****MPLE)' — article, platform, credential, hint."""
    platform = facts["platform_name"]
    ctype = facts.get("credential_type") or ""
    name = _CREDENTIAL_NAMES.get(ctype, ctype.replace("_", " ") or "credential")
    article = "An" if platform[:1].upper() in "AEIOU" else "A"
    hint = facts.get("credential_hint")
    return f"{article} {platform} {name}" + (f" ({hint})" if hint else "")


def deterministic_sections(facts: dict) -> dict:
    """Template prose built purely from facts — always grounded, never fluent."""
    audit_log = facts["audit_log"]
    duration = facts["exposure_duration"]
    severity = facts["severity"]

    if facts["event_count"] == 0:
        summary = (
            f"{_what(facts)} was exposed in a public repository for {duration}. "
            f"No activity was recorded in {audit_log} during the investigation window. "
            "This does not prove the credential went unused, so treat it as compromised."
        )
        narrative = [
            f"No events were recorded in {audit_log}. {facts.get('blind_spot', '')}".strip()
        ]
        impact = (
            "No financial or data impact could be measured from the audit log. "
            "Rotate the credential as urgently as if activity had been found."
        )
        return {"executive_summary": summary, "narrative": narrative, "business_impact": impact}

    worst = next(iter(facts["categories"]), None)
    summary = (
        f"{_what(facts)} was exposed in a public repository for {duration}. "
        f"{audit_log} recorded {facts['event_count']} event(s) between "
        f"{facts['first_event']} and {facts['last_event']}"
        + (f", the most serious being {CATEGORY_LABELS.get(worst, worst)}" if worst else "")
        + f". Overall severity: {severity}."
    )

    narrative = []
    # facts["actions"] is ranked worst-first to choose what to show; the
    # narrative itself reads in time order.
    for action in sorted(facts["actions"], key=lambda a: a["first_seen"] or ""):
        name = action["label"] or action["action"]
        line = f"{action['first_seen']}: {name} ({action['action']})"
        if action["count"] > 1:
            line += f", {action['count']} times"
        if action["resources"]:
            line += f" on {', '.join(action['resources'])}"
        if action["failed"]:
            line += f" ({action['failed']} failed)"
        narrative.append(line + ".")
    if facts.get("other_action_count"):
        narrative.append(f"{facts['other_action_count']} other kind(s) of action were also recorded.")

    impact_parts = []
    if facts["financial"]:
        impact_parts.append("Financial impact: " + "; ".join(facts["financial"]) + ".")
    else:
        impact_parts.append("No direct financial impact was measured.")
    impact_parts.extend(facts["compliance"])
    if facts["event_count"] and not facts["source_ips"]:
        impact_parts.append(f"{audit_log} does not record source IP addresses for this activity.")

    return {
        "executive_summary": summary,
        "narrative": narrative,
        "business_impact": " ".join(impact_parts),
    }


def render_report(facts: dict, sections: dict) -> str:
    """Markdown report from writer sections plus the deterministic checklist."""
    lines = [
        "## Executive Summary",
        "",
        sections["executive_summary"],
        "",
        "## What Happened",
        "",
        *[f"- {step}" for step in sections["narrative"]],
        "",
        "## Business Impact",
        "",
        sections["business_impact"],
        "",
        "## Remediation Checklist",
        "",
        *[f"{i}. {step}" for i, step in enumerate(build_remediation(facts), start=1)],
    ]
    return "\n".join(lines).strip() + "\n"
