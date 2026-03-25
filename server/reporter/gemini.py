"""
Gemini-powered forensic report generator.
Takes classified events + incident metadata → readable report.
"""

import google.generativeai as genai

from config import get_settings
from normalizer.schema import ForensicEvent, IncidentRecord

settings = get_settings()


def generate_report(incident: IncidentRecord) -> tuple[str, list[str]]:
    """
    Generate a forensic report using Gemini.
    Returns (report_text, remediation_steps).
    Falls back to template-based report on API failure.
    """
    if not settings.GEMINI_API_KEY:
        return _template_report(incident)

    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")

    prompt = _build_prompt(incident)

    try:
        response = model.generate_content(prompt)
        text = response.text

        # Parse remediation steps from the output
        steps = _parse_remediation_steps(text)
        return text, steps
    except Exception:
        return _template_report(incident)


def _build_prompt(incident: IncidentRecord) -> str:
    duration = "ongoing"
    if incident.exposure_end:
        delta = incident.exposure_end - incident.exposure_start
        total_s = int(delta.total_seconds())
        mins, secs = divmod(total_s, 60)
        hours, mins = divmod(mins, 60)
        parts = []
        if hours:
            parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
        if mins:
            parts.append(f"{mins} minute{'s' if mins > 1 else ''}")
        if secs:
            parts.append(f"{secs} second{'s' if secs > 1 else ''}")
        duration = " ".join(parts)

    events_text = "\n".join(
        f"  {e.timestamp} - {e.api_action} from {e.source_ip or 'unknown'} on {e.affected_resource or 'N/A'} (severity: {e.impact_category or 'unclassified'})"
        for e in incident.events
    )

    categories = {e.impact_category for e in incident.events if e.impact_category}
    highest = max((e.severity_weight or 0) for e in incident.events) if incident.events else 0

    return f"""You are a security analyst writing a forensic incident report.

CONTEXT:
- Credential type: {incident.credential_type}
- Repository: {incident.repo_url}
- Exposure start: {incident.exposure_start}
- Exposure end: {incident.exposure_end or 'still open'}
- Exposure duration: {duration}
- Total events: {len(incident.events)}
- Platforms affected: AWS CloudTrail
- Highest severity category: weight {highest}

EVENTS:
{events_text}

STATISTICS:
- Categories seen: {', '.join(categories) if categories else 'none'}

Generate a forensic incident report in four sections:
(1) Executive Summary (1 paragraph, plain English, no jargon)
(2) Chronological Narrative (what the attacker did, step by step)
(3) Business Impact Assessment
(4) Remediation Checklist (number each item, start each with ☐, be specific — include exact resource names and AWS CLI commands where applicable)

The audience is a developer with no security background. Avoid acronyms like MITRE, TTPs, CVE. Use plain language.
If any resource name contains words like users, customers, email, pii — flag this explicitly as a GDPR notification requirement in the Executive Summary.
Keep the entire report under 400 words. Be specific about resource names — use the exact resource names provided."""


def _parse_remediation_steps(report_text: str) -> list[str]:
    """Extract ☐ checklist items from the report."""
    steps: list[str] = []
    for line in report_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("☐"):
            steps.append(stripped[1:].strip())
    return steps


def _template_report(incident: IncidentRecord) -> tuple[str, list[str]]:
    """Fallback template-based report when Gemini is unavailable."""
    event_count = len(incident.events)
    categories = {e.impact_category for e in incident.events if e.impact_category}
    sources = {e.source_ip for e in incident.events if e.source_ip}

    report = f"""BREACHTRACE INCIDENT REPORT
===========================
Credential: {incident.credential_hint}
Repository: {incident.repo_url}
Exposed: {incident.exposure_start}
Revoked: {incident.exposure_end or 'Still open'}
Status: {incident.overall_severity or 'Pending'}

SUMMARY
-------
{event_count} forensic event(s) detected during the exposure window.
Categories: {', '.join(categories) if categories else 'None classified'}.
Source IPs: {', '.join(sources) if sources else 'None detected'}.

REMEDIATION
-----------
☐ Rotate the exposed credential immediately
☐ Review all events in the forensic timeline
☐ Audit affected resources for unauthorized changes
"""

    steps = [
        "Rotate the exposed credential immediately",
        "Review all events in the forensic timeline",
        "Audit affected resources for unauthorized changes",
    ]

    return report, steps
