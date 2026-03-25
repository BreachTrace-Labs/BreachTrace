"""
Severity scoring — aggregates classified events into an overall severity level.
"""

from normalizer.schema import ForensicEvent

PII_KEYWORDS = {"user", "customer", "pii", "email", "personal", "private"}

WEIGHT_TO_SEVERITY = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Low"}


def score_incident(events: list[ForensicEvent]) -> str:
    """Compute overall incident severity from classified events."""
    if not events:
        return "Low"

    categories = {e.impact_category for e in events if e.impact_category}

    # Critical triggers
    critical_categories = {"privilege_escalation", "exfiltration", "code_compromise"}
    if categories & critical_categories:
        return "Critical"

    max_weight = max((e.severity_weight or 0) for e in events)

    # Financial abuse escalation
    if "financial_abuse" in categories:
        return "Critical" if max_weight >= 3 else "High"

    return WEIGHT_TO_SEVERITY.get(max_weight, "Low")


def check_gdpr_flag(events: list[ForensicEvent]) -> bool:
    """Check if any data_access / exfiltration event touches PII resources."""
    for event in events:
        if event.impact_category not in ("data_access", "exfiltration"):
            continue
        resource = (event.affected_resource or "").lower()
        if any(kw in resource for kw in PII_KEYWORDS):
            return True
    return False


def compute_financial_impact(events: list[ForensicEvent]) -> str | None:
    """Estimate financial impact from resource_abuse events."""
    ec2_count = sum(
        1
        for e in events
        if e.api_action == "RunInstances" and e.success
    )
    data_access_count = sum(
        1
        for e in events
        if e.api_action == "GetObject" and e.success
    )

    parts: list[str] = []
    if ec2_count:
        parts.append(f"EC2: {ec2_count}x instances at ~$0.02/hr")
    if data_access_count:
        parts.append(f"S3 data transfer: ~{data_access_count} object(s) retrieved")

    return ". ".join(parts) if parts else None
