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

from dataclasses import dataclass

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


def impact_evidence(events):
    """Failed AWS and GCP operations are attempts, not completed impact."""
    return [event for event in events
            if getattr(event, 'platform', None) not in ('aws', 'gcp') or getattr(event, 'success', None) is True]


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
    events = impact_evidence(events)
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


NO_FINANCIAL_IMPACT = "No financial impact detected"
GCP_FINANCIAL_UNAVAILABLE = "GCP billing data is not available from Cloud Audit Logs; charges and loss cannot be determined."


@dataclass(frozen=True)
class FinancialImpactLine:
    """
    One costed finding, in structured form.

    ``text`` is the human-readable sentence and is the single source of truth for
    the joined string ``compute_financial_impact()`` returns — the two views can
    never drift because one is derived from the other.

    The distinction that matters most is ``actual``. Stripe events carry a real
    transacted amount. Twilio may supply a recorded per-resource charge; neither
    that charge nor the surrounding event is proof of use by a particular key.
    Other amounts may be estimates from public list prices.
    """

    platform: str            # aws | gcp | azure | stripe | twilio
    kind: str                # compute|egress|database|cluster|charge|refund|payout|messaging|number
    label: str               # 'EC2' | 'Cloud Storage egress' | 'Stripe'
    text: str                # the rendered sentence
    amount: float | None     # numeric magnitude, in major currency units
    currency: str | None     # ISO code — set only where the amount is real money
    unit: str | None         # None | 'hour' | 'day' | 'month' — rate denominator
    quantity: int | None     # 2 instances / 2 transactions / 14 messages
    actual: bool             # True only where money demonstrably moved


def compute_financial_impact_lines(
    events: list[ForensicEvent],
) -> list[FinancialImpactLine]:
    """
    Structured financial impact, one line per costed finding.

    Each platform contributes its own lines and they are concatenated, so a
    single leak that exposed both an AWS key and a Stripe key reports both.
    Events with no platform default to 'aws', matching the schema default.
    """
    if not events:
        return []

    by_platform: dict[str, list[ForensicEvent]] = {}
    for event in events:
        platform = (getattr(event, "platform", None) or "aws").lower()
        if platform == 'gcp' and getattr(event, 'success', None) is not True:
            continue
        by_platform.setdefault(platform, []).append(event)

    handlers = {
        "aws": _aws_impacts,
        "gcp": _gcp_impacts,
        "azure": _azure_impacts,
        "stripe": _stripe_impacts,
        "twilio": _twilio_impacts,
    }

    lines: list[FinancialImpactLine] = []
    # Stable ordering so report text does not churn between runs.
    for platform in ("aws", "gcp", "azure", "stripe", "twilio"):
        platform_events = by_platform.get(platform)
        if platform_events:
            lines.extend(handlers[platform](platform_events))

    return lines


def compute_financial_impact(events: list[ForensicEvent]) -> str:
    """
    Estimate financial impact from detected resource abuse, across every platform.

    The joined-string view of ``compute_financial_impact_lines()``. Kept as the
    stored/report-facing form; its output is pinned by tests and unchanged.

    Returns:
        str: e.g. 'EC2: 2x t2.micro at $0.02/hr. Stripe: $412.50 charged (3 charges)'
             or 'No financial impact detected'
    """
    lines = compute_financial_impact_lines(events)
    if not lines:
        if any(getattr(event, 'platform', None) == 'gcp' for event in events):
            return GCP_FINANCIAL_UNAVAILABLE
        return NO_FINANCIAL_IMPACT

    return ". ".join(line.text for line in lines)


def _aws_impacts(events: list[ForensicEvent]) -> list[FinancialImpactLine]:
    """AWS cost lines. Output format is pinned by tests — do not reword."""
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

    impacts: list[FinancialImpactLine] = []

    # EC2 cost estimate: assume t2.micro at $0.0116/hour
    if ec2_launches > 0:
        hourly_cost = ec2_launches * 0.0116
        impacts.append(FinancialImpactLine(
            platform="aws", kind="compute", label="EC2",
            text=f"EC2: {ec2_launches}x t2.micro at ${hourly_cost:.2f}/hr",
            amount=hourly_cost, currency="USD", unit="hour",
            quantity=ec2_launches, actual=False,
        ))

    # Data transfer cost: assume $0.09 per GB transferred
    if get_objects > 0:
        # Rough estimate: assume avg 100MB per GetObject = 0.1 GB
        gb_transferred = get_objects * 0.1
        transfer_cost = gb_transferred * 0.09
        impacts.append(FinancialImpactLine(
            platform="aws", kind="egress", label="Data transfer",
            text=f"Data transfer: estimated ${transfer_cost:.2f}",
            amount=transfer_cost, currency="USD", unit=None,
            quantity=get_objects, actual=False,
        ))

    # Database cost estimate: assume RDS multi-az at ~$1.50/day
    if db_creates > 0:
        db_cost = db_creates * 1.50
        impacts.append(FinancialImpactLine(
            platform="aws", kind="database", label="RDS",
            text=f"RDS: {db_creates} instance(s) at ${db_cost:.2f}/day",
            amount=db_cost, currency="USD", unit="day",
            quantity=db_creates, actual=False,
        ))

    # EKS cluster cost: ~$0.10 per cluster hour
    if cluster_creates > 0:
        cluster_cost = cluster_creates * 0.10
        impacts.append(FinancialImpactLine(
            platform="aws", kind="cluster", label="EKS",
            text=f"EKS: {cluster_creates} cluster(s) at ${cluster_cost:.2f}/hr",
            amount=cluster_cost, currency="USD", unit="hour",
            quantity=cluster_creates, actual=False,
        ))

    return impacts


# ---------------------------------------------------------------------------
# Per-platform cost models
#
# Rates are public list prices for the cheapest common instance class, captured
# 2026-08. They are order-of-magnitude estimates for a developer-facing report,
# not billing-accurate figures — the report says "estimated" for exactly this
# reason. Stripe and Twilio are the exceptions: those are real transacted
# amounts and real per-message rates.
# ---------------------------------------------------------------------------

_AZURE_B1S_HOURLY = 0.0104
_AZURE_EGRESS_PER_GB = 0.087
_AZURE_AKS_CLUSTER_HOURLY = 0.10
_AZURE_SQL_DAILY = 1.50

_TWILIO_SMS_COST = 0.0079
_TWILIO_CALL_COST = 0.014
_TWILIO_NUMBER_MONTHLY = 1.15

# Assumed payload size per bulk read, mirroring the AWS estimate of 100 MB.
_ASSUMED_OBJECT_GB = 0.1


def _count(events: list[ForensicEvent], *actions: str) -> int:
    return sum(1 for e in events if e.api_action in actions)


def _gcp_impacts(events: list[ForensicEvent]) -> list[FinancialImpactLine]:
    """Audit methods alone cannot establish machine sizes, transfer or bills."""
    return []


def _azure_impacts(events: list[ForensicEvent]) -> list[FinancialImpactLine]:
    """
    Azure operation names are slash-separated resource provider paths, e.g.
    'Microsoft.Compute/virtualMachines/write'. Matching is case-insensitive
    because the Activity Log is inconsistent about casing.
    """
    impacts: list[FinancialImpactLine] = []
    actions = [(e.api_action or "").lower() for e in events]

    vm_creates = sum(1 for a in actions if a.endswith("microsoft.compute/virtualmachines/write"))
    aks_creates = sum(
        1 for a in actions if a.endswith("microsoft.containerservice/managedclusters/write")
    )
    sql_creates = sum(1 for a in actions if "microsoft.sql/servers/databases/write" in a)
    bulk_reads = sum(
        1
        for e in events
        if "microsoft.storage" in (e.api_action or "").lower()
        and (e.api_action or "").lower().endswith("/read")
        and e.affected_resource
        and _is_large_object(e.affected_resource)
    )

    if vm_creates > 0:
        cost = vm_creates * _AZURE_B1S_HOURLY
        impacts.append(FinancialImpactLine(
            platform="azure", kind="compute", label="Virtual Machines",
            text=f"Virtual Machines: {vm_creates}x B1s at ${cost:.2f}/hr",
            amount=cost, currency="USD", unit="hour",
            quantity=vm_creates, actual=False,
        ))
    if bulk_reads > 0:
        cost = bulk_reads * _ASSUMED_OBJECT_GB * _AZURE_EGRESS_PER_GB
        impacts.append(FinancialImpactLine(
            platform="azure", kind="egress", label="Blob Storage egress",
            text=f"Blob Storage egress: estimated ${cost:.2f}",
            amount=cost, currency="USD", unit=None,
            quantity=bulk_reads, actual=False,
        ))
    if aks_creates > 0:
        cost = aks_creates * _AZURE_AKS_CLUSTER_HOURLY
        impacts.append(FinancialImpactLine(
            platform="azure", kind="cluster", label="AKS",
            text=f"AKS: {aks_creates} cluster(s) at ${cost:.2f}/hr",
            amount=cost, currency="USD", unit="hour",
            quantity=aks_creates, actual=False,
        ))
    if sql_creates > 0:
        cost = sql_creates * _AZURE_SQL_DAILY
        impacts.append(FinancialImpactLine(
            platform="azure", kind="database", label="Azure SQL",
            text=f"Azure SQL: {sql_creates} database(s) at ${cost:.2f}/day",
            amount=cost, currency="USD", unit="day",
            quantity=sql_creates, actual=False,
        ))

    return impacts


# Stripe emits several events per payment — payment_intent.created,
# payment_intent.succeeded, charge.succeeded, charge.updated — and every one of
# them carries the full amount. Summing them reported a single $10 payment as
# $40. Money is therefore counted once per underlying object, and only from the
# events that mean it actually moved. `charge.failed` and friends carry an
# amount too, but nothing was charged.
_STRIPE_CHARGE_EVENTS = frozenset({
    "charge.succeeded", "charge.captured", "payment_intent.succeeded",
})
_STRIPE_PAYOUT_EVENTS = frozenset({"payout.paid"})
_STRIPE_ZERO_DECIMAL = frozenset({"BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "VND", "VUV", "XAF", "XOF", "XPF"})


def _stripe_object(event: ForensicEvent) -> dict | None:
    """The `data.object` payload of a stored Stripe event, if well-formed."""
    raw = getattr(event, "raw_data", None)
    if not isinstance(raw, dict):
        return None
    data = raw.get("data")
    obj = data.get("object") if isinstance(data, dict) else None
    return obj if isinstance(obj, dict) else None


def _minor_units(obj: dict, *fields: str) -> float | None:
    """First numeric Stripe amount converted to the currency's major units."""
    for field in fields:
        value = obj.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            divisor = 1 if str(obj.get("currency") or "").upper() in _STRIPE_ZERO_DECIMAL else 100
            return float(value) / divisor
    return None


def _stripe_impacts(events: list[ForensicEvent]) -> list[FinancialImpactLine]:
    """
    Stripe reports real money, not an estimated rate. This is the single most
    concrete financial figure BreachTrace can produce, so charges, refunds and
    payouts are reported separately rather than netted — they are different
    harms.

    Every figure is keyed by the Stripe object it belongs to, so the multiple
    events Stripe emits for one payment, refund or payout count once. Events
    without an object id (hand-built fixtures) fall back to the event's own id.
    """
    # key -> (amount, currency); max() keeps the final captured/refunded total.
    charges: dict[str, tuple[float, str]] = {}
    refunds: dict[str, tuple[float, str]] = {}
    refunded_charges: dict[str, tuple[float, str]] = {}  # from charge.refunded
    charges_with_refund_objects: set[str] = set()
    payouts: dict[str, tuple[float, str]] = {}

    def _keep_max(bucket: dict[str, tuple[float, str]], key: str, amount: float, currency: str) -> None:
        if key not in bucket or amount > bucket[key][0]:
            bucket[key] = (amount, currency)

    for event in events:
        action = (event.api_action or "").lower()
        obj = _stripe_object(event)
        if obj is None:
            continue
        currency = str(obj.get("currency") or "usd").upper()
        fallback_key = str(getattr(event, "event_id", None) or id(event))
        obj_id = obj.get("id") or fallback_key

        if action in _STRIPE_CHARGE_EVENTS:
            # A charge and its payment intent are the same money.
            key = obj.get("payment_intent") if obj.get("object") == "charge" else None
            amount = _minor_units(obj, "amount_received", "amount", "amount_captured")
            if amount is not None:
                _keep_max(charges, str(key or obj_id), amount, currency)
        elif action == "refund.created":
            amount = _minor_units(obj, "amount")
            if amount is not None:
                _keep_max(refunds, str(obj_id), amount, currency)
                if obj.get("charge"):
                    charges_with_refund_objects.add(str(obj["charge"]))
        elif action == "charge.refunded":
            # The payload is the CHARGE: `amount` is what was charged, and
            # `amount_refunded` is the cumulative refunded total.
            amount = _minor_units(obj, "amount_refunded", "amount")
            if amount is not None:
                _keep_max(refunded_charges, str(obj_id), amount, currency)
        elif action in _STRIPE_PAYOUT_EVENTS:
            amount = _minor_units(obj, "amount")
            if amount is not None:
                _keep_max(payouts, str(obj_id), amount, currency)

    # charge.refunded only fills the gap where no refund.created was recorded.
    for charge_id, value in refunded_charges.items():
        if charge_id not in charges_with_refund_objects:
            refunds[f"charge:{charge_id}"] = value

    def _lines(
        bucket: dict[str, tuple[float, str]], kind: str, verb: str, noun: str
    ) -> list[FinancialImpactLine]:
        totals: dict[str, float] = {}
        counts: dict[str, int] = {}
        for amount, currency in bucket.values():
            totals[currency] = totals.get(currency, 0.0) + amount
            counts[currency] = counts.get(currency, 0) + 1
        return [
            FinancialImpactLine(
                platform="stripe", kind=kind, label="Stripe",
                text=f"Stripe: {total:,.2f} {currency} {verb} ({counts[currency]} {noun})",
                amount=total, currency=currency, unit=None,
                quantity=counts[currency],
                # The only place in the system where money demonstrably moved.
                actual=True,
            )
            for currency, total in sorted(totals.items())
        ]

    return (
        _lines(charges, "charge", "charged", "transaction(s)")
        + _lines(refunds, "refund", "refunded", "refund(s)")
        + _lines(payouts, "payout", "paid out", "payout(s)")
    )


# Twilio actions that describe reading data rather than a billable send.
_TWILIO_NON_BILLABLE_SUFFIXES = (".read", ".list")


def _twilio_cost(events: list[ForensicEvent], estimate_each: float) -> float:
    """
    Billed cost of a set of Twilio messages or calls.

    The collector stores Twilio's own per-item price, which already reflects
    segments, destination and call duration. The flat list-price estimate is
    used only for items Twilio has not priced yet (price is null until the
    message or call is finalised).
    """
    total = 0.0
    for event in events:
        raw = getattr(event, "raw_data", None)
        price = raw.get("price") if isinstance(raw, dict) else None
        if isinstance(price, (int, float)) and not isinstance(price, bool):
            total += abs(float(price))
        else:
            total += estimate_each
    return total


def _twilio_impacts(events: list[ForensicEvent]) -> list[FinancialImpactLine]:
    """Twilio abuse is billed per message/call, so volume maps directly to cost."""
    impacts: list[FinancialImpactLine] = []

    def _billable(prefix: str) -> list[ForensicEvent]:
        return [
            e for e in events
            if (e.api_action or "").lower().startswith(prefix)
            and not (e.api_action or "").lower().endswith(_TWILIO_NON_BILLABLE_SUFFIXES)
            and getattr(e, "event_source", None) != "monitor.twilio.com"
        ]

    message_events = _billable("message.")
    call_events = _billable("call.")
    actions = [(e.api_action or "").lower() for e in events]
    numbers = sum(1 for a in actions if "number" in a and ("purchase" in a or "create" in a))

    for label, group in (("message", message_events), ("call", call_events)):
        priced: dict[str, list[float]] = {}
        pending = 0
        for event in group:
            raw = getattr(event, "raw_data", None) or {}
            price, unit = raw.get("price"), raw.get("price_unit")
            if isinstance(price, (int, float)) and not isinstance(price, bool) and isinstance(unit, str) and len(unit) == 3 and unit.isalpha():
                priced.setdefault(unit.upper(), []).append(abs(float(price)))
            else:
                pending += 1
        for currency, amounts in sorted(priced.items()):
            total = sum(amounts)
            impacts.append(FinancialImpactLine(
                platform="twilio", kind="messaging", label="Twilio",
                text=f"Twilio: {len(amounts)} {label}(s) with recorded charges of {currency} {total:.4f}",
                amount=total, currency=currency, unit=None, quantity=len(amounts), actual=True,
            ))
        if pending:
            impacts.append(FinancialImpactLine(
                platform="twilio", kind="messaging", label="Twilio",
                text=f"Twilio: {pending} {label}(s) with price unavailable or pending",
                amount=None, currency=None, unit=None, quantity=pending, actual=False,
            ))
    if numbers > 0:
        cost = numbers * _TWILIO_NUMBER_MONTHLY
        impacts.append(FinancialImpactLine(
            platform="twilio", kind="number", label="Twilio",
            text=f"Twilio: {numbers} number(s) purchased at ${cost:.2f}/month",
            amount=cost, currency="USD", unit="month",
            quantity=numbers, actual=False,
        ))

    return impacts


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

    for event in impact_evidence(events):
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
    for event in impact_evidence(events):
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
        for event in impact_evidence(events)
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
    events = impact_evidence(events)
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
            f"GDPR Articles 32/33: A data-access event refers to a resource whose name may suggest personal data{resource_hint}. "
            "Review whether personal data is involved and whether notification obligations apply."
        )

    if pcidss:
        fin_events = [e for e in events if e.impact_category == "financial_abuse"]
        if fin_events:
            reasons.append(
                "PCI-DSS Requirement 12: An event was classified as financial activity. "
                "Review whether the affected environment is in PCI DSS scope and assess incident response obligations."
            )
        else:
            reasons.append(
                "PCI-DSS Requirement 12: An event refers to a resource with a payment-related name. "
                "Review whether cardholder data or an in-scope environment is involved."
            )

    if soc2:
        reasons.append(
            "SOC 2 (CC6 / A1): An event was classified as privilege escalation, exfiltration, "
            "or resource abuse. Review whether it relates to controls in your SOC 2 scope."
        )

    return reasons


def _is_large_object(resource_name: str) -> bool:
    """Heuristic to detect if a resource name indicates a large object."""
    # Look for size hints in the resource name
    size_indicators = ("large", "big", "archive", "backup", "export", "dump")
    resource_lower = resource_name.lower()
    return any(indicator in resource_lower for indicator in size_indicators)
