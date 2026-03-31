"""
Incident severity scoring and financial impact estimation.

This module provides three main functions:
1.⁠ ⁠score_incident() - Returns 'Low', 'Medium', 'High', or 'Critical'
2.⁠ ⁠compute_financial_impact() - Estimates cost impact from resource abuse
3.⁠ ⁠check_gdpr_flag() - Detects PII/personal data exposure

Severity Rules (in order of precedence):
•⁠  ⁠If any of {privilege_escalation, exfiltration, code_compromise} → Critical
•⁠  ⁠If financial_abuse + max_weight >= 3 → Critical; else if financial_abuse → High
•⁠  ⁠Otherwise: map max_weight (4→Critical, 3→High, 2→Medium, 1→Low, 0→Low)
"""

from normalizer.schema import ForensicEvent

# Map severity weights to human-readable labels
_WEIGHT_TO_LABEL = {
    0: "Low",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

# Keywords indicating PII or personal data in resource names
PII_HINTS = (
    "user",
    "customer",
    "account",
    "personal",
    "pii",
    "email",
    "phone",
    "ssn",
    "passport",
    "private",
    "confidential",
)

# High-impact categories that always trigger Critical severity
CRITICAL_CATEGORIES = {"privilege_escalation", "exfiltration", "code_compromise"}


def score_incident(events: list[ForensicEvent]) -> str:
    """
    Aggregate per-event severity weights into an overall incident severity label.

    Logic:
    1. Collect all distinct impact_category values from events with categories assigned.
    2. If any of {privilege_escalation, exfiltration, code_compromise} present → 'Critical'
    3. Find max severity_weight across all events.
    4. If financial_abuse present and max_weight >= 3 → 'Critical'
    5. Else if financial_abuse present → 'High'
    6. Otherwise map max_weight: 4→'Critical', 3→'High', 2→'Medium', 1→'Low', 0→'Low'

    Args:
        events: List of ForensicEvent objects with impact_category and severity_weight set.

    Returns:
        str: One of 'Low', 'Medium', 'High', or 'Critical'
    """
    if not events:
        return "Low"

    # Collect all distinct categories
    categories = {e.impact_category for e in events if e.impact_category}

    # Rule 1: Check for critical categories
    if categories & CRITICAL_CATEGORIES:
        return "Critical"

    # Find max severity weight
    weights = [e.severity_weight for e in events if e.severity_weight is not None]
    max_weight = max(weights, default=0)

    # Rule 2: Financial abuse escalation
    if "financial_abuse" in categories:
        if max_weight >= 3:
            return "Critical"
        return "High"

    # Rule 3: Default mapping by weight
    return _WEIGHT_TO_LABEL.get(max_weight, "Low")


def compute_financial_impact(events: list[ForensicEvent]) -> str:
    """
    Estimate financial impact from detected resource abuse patterns.

    Scans for:
    - RunInstances calls → EC2 instance launch costs
    - GetObject calls with large resource indicators → data transfer costs
    - CreateCluster, CreateDBInstance → infrastructure costs

    Returns a human-readable impact string with estimated costs and affected resources.

    Args:
        events: List of ForensicEvent objects

    Returns:
        str: Formatted impact description, e.g.
             'EC2: 2x t2.micro at $0.02/hr. Data transfer: estimated $0.20'
             or 'No financial impact detected'
    """
    if not events:
        return "No financial impact detected"

    # Count resource abuse patterns
    ec2_launches = sum(1 for e in events if e.api_action == "RunInstances")
    get_objects = sum(
        1
        for e in events
        if e.api_action == "GetObject"
        and e.affected_resource
        and _is_large_object(e.affected_resource)
    )
    db_creates = sum(
        1
        for e in events
        if e.api_action in ("CreateDBInstance", "CreateDBCluster")
    )
    cluster_creates = sum(
        1
        for e in events
        if e.api_action == "CreateCluster"
        and getattr(e, "event_source", None) == "eks.amazonaws.com"
    )

    impacts = []

    # EC2 cost estimate: assume t2.micro at $0.0116/hour
    if ec2_launches > 0:
        hourly_cost = ec2_launches * 0.0116
        impacts.append(f"EC2: {ec2_launches}x t2.micro at ${hourly_cost:.2f}/hr")

    # Data transfer cost: assume $0.09 per GB transferred
    if get_objects > 0:
        # Rough estimate: assume avg 100MB per GetObject = 0.1 GB
        gb_transferred = get_objects * 0.1
        transfer_cost = gb_transferred * 0.09
        impacts.append(f"Data transfer: estimated ${transfer_cost:.2f}")

    # Database cost estimate: assume RDS multi-az at ~$1.50/day
    if db_creates > 0:
        db_cost = db_creates * 1.50
        impacts.append(f"RDS: {db_creates} instance(s) at ${db_cost:.2f}/day")

    # EKS cluster cost: ~$0.10 per cluster hour
    if cluster_creates > 0:
        cluster_cost = cluster_creates * 0.10
        impacts.append(f"EKS: {cluster_creates} cluster(s) at ${cluster_cost:.2f}/hr")

    if not impacts:
        return "No financial impact detected"

    return ". ".join(impacts)


def check_gdpr_flag(events: list[ForensicEvent]) -> bool:
    """
    Detect if any data access/exfiltration events touch PII-hinting resources.

    Scans affected_resource strings for keywords like 'user', 'customer', 'pii', 'email',
    'personal', 'private', 'confidential', etc.

    Args:
        events: List of ForensicEvent objects

    Returns:
        bool: True if any data_access or exfiltration event touches PII-hinting resource
    """
    sensitive_categories = {"data_access", "exfiltration"}

    for event in events:
        if (
            event.impact_category in sensitive_categories
            and event.affected_resource
            and any(hint in event.affected_resource.lower() for hint in PII_HINTS)
        ):
            return True

    return False


def _is_large_object(resource_name: str) -> bool:
    """Heuristic to detect if a resource name indicates a large object."""
    # Look for size hints in the resource name
    size_indicators = ("large", "big", "archive", "backup", "export", "dump")
    resource_lower = resource_name.lower()
    return any(indicator in resource_lower for indicator in size_indicators)