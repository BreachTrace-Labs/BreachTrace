"""
Incident severity scoring and financial impact estimation.

This module provides:
1. score_incident()        - Returns 'Low', 'Medium', 'High', or 'Critical'
2. compute_financial_impact() - Estimates cost impact from resource abuse
3. check_gdpr_flag()       - Detects PII/personal data exposure (GDPR Article 33)
4. check_pcidss_flag()     - Detects payment card data exposure (PCI-DSS Req. 12.10)
5. check_soc2_flag()       - Detects security/availability incidents (SOC 2 CC6/A1)

Severity Rules (in order of precedence):
- If any of {privilege_escalation, exfiltration, code_compromise} -> Critical
- If financial_abuse + max_weight >= 3 -> Critical; else if financial_abuse -> High
- Otherwise: map max_weight (4->Critical, 3->High, 2->Medium, 1->Low, 0->Low)
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

# ── GDPR Article 33 keywords ───────────────────────────────────────────────
# Resource names containing these strings in a data_access or exfiltration
# event indicate that personal data may have been accessed.
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
    "employee",
    "member",
    "patient",
    "profile",
    "address",
    "birth",
    "national",
    "medical",
    "health",
    "identity",
    "orders",
    "db",
    "database",
)

# ── PCI-DSS Requirement 12.10 keywords ────────────────────────────────────
# Payment card environment resource-name hints.
PCI_DSS_HINTS = (
    "payment",
    "card",
    "credit",
    "billing",
    "transaction",
    "stripe",
    "checkout",
    "invoice",
    "charge",
    "refund",
    "merchant",
    "cvv",
    "pan",
    "bank",
    "financial",
    "paypal",
    "braintree",
    "wallet",
    "debit",
    "cardholder",
)

# Categories where payment data access is PCI-DSS relevant
_PCI_DSS_SENSITIVE = frozenset({"data_access", "exfiltration", "financial_abuse"})

# ── SOC 2 relevant categories ──────────────────────────────────────────────
_SOC2_TRIGGER_CATEGORIES = frozenset({
    "privilege_escalation",
    "exfiltration",
    "resource_abuse",
})

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
    Detect if GDPR Article 33 breach notification may be required.

    Triggered when a data_access or exfiltration event touches a resource whose
    name contains PII-hinting keywords (user, customer, email, medical, etc.).

    Args:
        events: Classified ForensicEvent objects.

    Returns:
        bool: True if PII access was detected.
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


def check_pcidss_flag(events: list[ForensicEvent]) -> bool:
    """
    Detect if PCI-DSS Requirement 12.10 incident notification may be required.

    Triggered by:
    - Any financial_abuse event (directly implicates the payment card environment).
    - Data access or exfiltration touching resources with payment-related names
      (payment, card, billing, stripe, transaction, etc.).

    Args:
        events: Classified ForensicEvent objects.

    Returns:
        bool: True if a PCI-DSS reportable event was detected.
    """
    for event in events:
        if event.impact_category == "financial_abuse":
            return True
        if (
            event.impact_category in _PCI_DSS_SENSITIVE
            and event.affected_resource
            and any(hint in event.affected_resource.lower() for hint in PCI_DSS_HINTS)
        ):
            return True
    return False


def check_soc2_flag(events: list[ForensicEvent]) -> bool:
    """
    Detect if a SOC 2 security incident should be documented.

    Triggered by privilege escalation, data exfiltration, or large-scale
    resource abuse — all of which affect SOC 2 Trust Service Criteria
    CC6 (Logical Access) and A1 (Availability).

    Args:
        events: Classified ForensicEvent objects.

    Returns:
        bool: True if a SOC 2 reportable event was detected.
    """
    return any(
        event.impact_category in _SOC2_TRIGGER_CATEGORIES
        for event in events
        if event.impact_category
    )


def build_compliance_reasons(
    gdpr: bool,
    pcidss: bool,
    soc2: bool,
    events: list[ForensicEvent],
) -> list[str]:
    """
    Build human-readable compliance notification reasons for the incident report.

    Returns a list of strings, one per applicable regulation, describing the
    specific obligation and the triggering condition observed.
    """
    reasons: list[str] = []

    if gdpr:
        # Find a representative PII resource name to include in the message.
        pii_resources = [
            e.affected_resource
            for e in events
            if e.impact_category in {"data_access", "exfiltration"}
            and e.affected_resource
            and any(h in e.affected_resource.lower() for h in PII_HINTS)
        ]
        resource_hint = f" (e.g. '{pii_resources[0]}')" if pii_resources else ""
        reasons.append(
            f"GDPR Article 33: Personal data may have been accessed{resource_hint}. "
            "Notify your Data Protection Authority within 72 hours if a breach is confirmed."
        )

    if pcidss:
        fin_events = [e for e in events if e.impact_category == "financial_abuse"]
        if fin_events:
            reasons.append(
                "PCI-DSS Requirement 12.10: Financial abuse events detected in the payment "
                "card environment. Initiate your incident response plan immediately and "
                "notify your acquiring bank and card brands."
            )
        else:
            reasons.append(
                "PCI-DSS Requirement 12.10: Payment-related resources were accessed during "
                "the exposure window. Review cardholder data access logs and notify your "
                "acquiring bank if cardholder data was compromised."
            )

    if soc2:
        reasons.append(
            "SOC 2 (CC6 / A1): A security event affecting logical access controls or system "
            "availability was detected. Document this incident in your SOC 2 evidence records "
            "and inform your auditor at the next review cycle."
        )

    return reasons


def _is_large_object(resource_name: str) -> bool:
    """Heuristic to detect if a resource name indicates a large object."""
    # Look for size hints in the resource name
    size_indicators = ("large", "big", "archive", "backup", "export", "dump")
    resource_lower = resource_name.lower()
    return any(indicator in resource_lower for indicator in size_indicators)