"""
Compact, verified fact sheet for one incident.

Every number, name and verdict in a report comes from here. The report model
only turns these facts into prose; it never sees raw audit-log events and never
decides severity, money or remediation. That split is what lets a very small
model write an accurate report: the hard part (getting the facts right) is done
in code and is identical whichever writer runs.

Events are aggregated, never listed one by one. A Twilio SMS-pumping incident
can carry 5,000 events, and the sheet must stay a few hundred tokens long.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from classifier.taxonomy_aws import AWS_API_TAXONOMY
from classifier.taxonomy_azure import AZURE_API_TAXONOMY
from classifier.taxonomy_gcp import GCP_API_TAXONOMY
from classifier.taxonomy_stripe import STRIPE_API_TAXONOMY
from classifier.taxonomy_twilio import TWILIO_API_TAXONOMY
from reporter.profiles import get_profile
from scorer.severity import (
    build_compliance_reasons,
    check_gdpr_flag,
    check_pcidss_flag,
    check_soc2_flag,
    compute_financial_impact_lines,
)

_TAXONOMIES: dict[str, dict[str, dict]] = {
    "aws": AWS_API_TAXONOMY,
    "gcp": GCP_API_TAXONOMY,
    "azure": AZURE_API_TAXONOMY,
    "stripe": STRIPE_API_TAXONOMY,
    "twilio": TWILIO_API_TAXONOMY,
}

# Worst first. Drives which actions lead the narrative.
CATEGORY_ORDER = (
    "privilege_escalation",
    "exfiltration",
    "code_compromise",
    "financial_abuse",
    "resource_abuse",
    "communication_abuse",
    "data_access",
    "reconnaissance",
)

CATEGORY_LABELS = {
    "privilege_escalation": "privilege escalation",
    "exfiltration": "data exfiltration",
    "code_compromise": "code compromise",
    "financial_abuse": "financial abuse",
    "resource_abuse": "resource abuse",
    "communication_abuse": "communication abuse",
    "data_access": "data access",
    "reconnaissance": "reconnaissance",
}

_MAX_ACTIONS = 8
_MAX_LISTED = 5


def action_label(platform: str, action: str) -> str | None:
    """Human-readable label for an audit-log action, when the taxonomy has one."""
    taxonomy = _TAXONOMIES.get(platform, {})
    entry = taxonomy.get(action)
    if entry is None and platform == "aws":
        # AWS taxonomy keys are `service:Action`; CloudTrail reports `Action`.
        suffix = [v for k, v in taxonomy.items() if k.endswith(f":{action}")]
        entry = suffix[0] if len(suffix) == 1 else None
    return entry.get("label") if entry else None


def humanize_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    parts = []
    for unit, size in (("day", 86_400), ("hour", 3_600), ("minute", 60)):
        value, seconds = divmod(seconds, size)
        if value:
            parts.append(f"{value} {unit}{'s' if value != 1 else ''}")
    return " ".join(parts[:2])


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _category_rank(category: str | None) -> int:
    try:
        return CATEGORY_ORDER.index(category or "")
    except ValueError:
        return len(CATEGORY_ORDER)


def build_fact_sheet(
    events: Iterable[Any],
    *,
    platform: str,
    overall_severity: str,
    exposure_duration_seconds: int,
    credential_type: str | None = None,
    credential_hint: str | None = None,
) -> dict:
    """
    Aggregate classified events into the fact sheet every report writer uses.

    ``events`` may be ORM rows or Pydantic ForensicEvents; only attributes
    common to both are read.
    """
    events = list(events)
    platform = (platform or "aws").lower()
    profile = get_profile(platform)

    by_action: dict[str, list[Any]] = {}
    for event in events:
        by_action.setdefault(event.api_action, []).append(event)

    actions = []
    for action, group in by_action.items():
        group.sort(key=lambda e: e.timestamp)
        category = group[0].impact_category
        resources = Counter(e.affected_resource for e in group if e.affected_resource)
        actions.append({
            "action": action,
            "label": action_label(platform, action),
            "category": category,
            "severity_weight": max((e.severity_weight or 0) for e in group),
            "count": len(group),
            "failed": sum(1 for e in group if e.success is False),
            "first_seen": _iso(group[0].timestamp),
            "resources": [r for r, _ in resources.most_common(2)],
        })
    actions.sort(key=lambda a: (_category_rank(a["category"]), -a["severity_weight"], -a["count"]))

    categories = Counter(e.impact_category for e in events if e.impact_category)
    resources = Counter(e.affected_resource for e in events if e.affected_resource)
    source_ips = Counter(e.source_ip for e in events if e.source_ip)
    timestamps = sorted(e.timestamp for e in events)

    gdpr, pcidss, soc2 = check_gdpr_flag(events), check_pcidss_flag(events), check_soc2_flag(events)

    return {
        "platform": platform,
        "platform_name": profile.name,
        "audit_log": profile.audit_log,
        "credential_type": credential_type,
        "credential_hint": credential_hint,
        "severity": (overall_severity or "Low").capitalize(),
        "exposure_seconds": int(exposure_duration_seconds),
        "exposure_duration": humanize_duration(exposure_duration_seconds),
        "event_count": len(events),
        "failed_count": sum(1 for e in events if e.success is False),
        "first_event": _iso(timestamps[0]) if timestamps else None,
        "last_event": _iso(timestamps[-1]) if timestamps else None,
        "categories": {
            c: categories[c]
            for c in sorted(categories, key=_category_rank)
        },
        "actions": actions[:_MAX_ACTIONS],
        "other_action_count": max(0, len(actions) - _MAX_ACTIONS),
        "resources": [r for r, _ in resources.most_common(_MAX_LISTED)],
        "source_ips": [ip for ip, _ in source_ips.most_common(_MAX_LISTED)],
        "financial": [line.text for line in compute_financial_impact_lines(events)],
        "compliance": build_compliance_reasons(gdpr=gdpr, pcidss=pcidss, soc2=soc2, events=events),
        "blind_spot": profile.blind_spot,
    }
