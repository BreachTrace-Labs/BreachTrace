from normalizer.schema import ForensicEvent

_SEVERITY_LABELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

PII_HINTS = ("user", "customer", "account", "personal", "pii", "email", "phone", "ssn", "passport")


def compute_severity(events: list[ForensicEvent]) -> tuple[str, bool]:
    """
    Aggregate per-event severity weights into an overall incident severity label.
    Also returns a GDPR flag if any data_access/exfiltration event touches a PII-hinting resource.

    Returns:
        (overall_severity: str, gdpr_flag: bool)
    TODO (Ritwik/Day 4): wire into pipeline.
    """
    if not events:
        return "NONE", False

    weights = [e.severity_weight for e in events if e.severity_weight is not None]
    max_weight = max(weights, default=0)
    overall = _SEVERITY_LABELS.get(max_weight, "UNKNOWN")

    gdpr_flag = any(
        e.impact_category in ("data_access", "data_exfiltration")
        and e.affected_resource
        and any(hint in e.affected_resource.lower() for hint in PII_HINTS)
        for e in events
    )

    return overall, gdpr_flag
