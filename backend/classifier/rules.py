from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from classifier.taxonomy_aws import AWS_API_TAXONOMY
from classifier.taxonomy_azure import AZURE_API_TAXONOMY
from classifier.taxonomy_gcp import GCP_API_TAXONOMY
from classifier.taxonomy_stripe import STRIPE_API_TAXONOMY
from classifier.taxonomy_twilio import TWILIO_API_TAXONOMY, TWILIO_BULK_THRESHOLD
from db.models import ForensicEvent as ORMForensicEvent
from db.models import IncidentRecord
from normalizer.schema import ForensicEvent

RECONNAISSANCE = "reconnaissance"
DATA_ACCESS = "data_access"
DATA_EXFILTRATION = "exfiltration"
RESOURCE_ABUSE = "resource_abuse"
PRIVILEGE_ESCALATION = "privilege_escalation"
FINANCIAL_ABUSE = "financial_abuse"
COMMUNICATION_ABUSE = "communication_abuse"
CODE_COMPROMISE = "code_compromise"

BULK_THRESHOLD = 5  # same api_action + same IP >= 5 times -> escalate to exfiltration

# ────────────────────────────────────────────────────────────────────────────
# Platform → taxonomy dispatch table
# ────────────────────────────────────────────────────────────────────────────
_TAXONOMY_MAP: dict[str, dict[str, dict]] = {
    "aws": AWS_API_TAXONOMY,
    "gcp": GCP_API_TAXONOMY,
    "azure": AZURE_API_TAXONOMY,
    "stripe": STRIPE_API_TAXONOMY,
    "twilio": TWILIO_API_TAXONOMY,
}

# Bulk-escalation threshold per platform.
#
# BULK_THRESHOLD = 5 was tuned for AWS GetObject, where five reads of the same
# object from one IP is already suspicious. That figure does not transfer:
# five Twilio messages is a normal application minute, and applying the AWS
# number there would mark every healthy integration as critical.
_BULK_THRESHOLD_BY_PLATFORM: dict[str, int] = {
    "twilio": TWILIO_BULK_THRESHOLD,
}


def _bulk_threshold(platform: str | None) -> int:
    return _BULK_THRESHOLD_BY_PLATFORM.get((platform or "aws").lower(), BULK_THRESHOLD)

# ────────────────────────────────────────────────────────────────────────────
# AWS heuristics (unchanged)
# ────────────────────────────────────────────────────────────────────────────
HEURISTIC_CLASSIFICATIONS: list[tuple[tuple[str, ...], tuple[str, int]]] = [
    (("List", "Describe"), (RECONNAISSANCE, 1)),
    (("Get",), (DATA_ACCESS, 2)),
    (("Put", "Create", "Delete", "Update", "Modify", "Run", "Start", "Stop", "Terminate"), (RESOURCE_ABUSE, 3)),
]

SPECIAL_OVERRIDES: dict[str, tuple[str, int]] = {
    "CreateAccessKey": (PRIVILEGE_ESCALATION, 4),
    "AttachUserPolicy": (PRIVILEGE_ESCALATION, 4),
    "AttachRolePolicy": (PRIVILEGE_ESCALATION, 4),
    "AttachGroupPolicy": (PRIVILEGE_ESCALATION, 4),
    "PutUserPolicy": (PRIVILEGE_ESCALATION, 4),
    "PutRolePolicy": (PRIVILEGE_ESCALATION, 4),
    "PutGroupPolicy": (PRIVILEGE_ESCALATION, 4),
    "PassRole": (PRIVILEGE_ESCALATION, 4),
    "AssumeRole": (PRIVILEGE_ESCALATION, 4),
    "CreateLoginProfile": (PRIVILEGE_ESCALATION, 4),
    "CreatePolicyVersion": (PRIVILEGE_ESCALATION, 4),
    "SetDefaultPolicyVersion": (PRIVILEGE_ESCALATION, 4),
    "UpdateAssumeRolePolicy": (PRIVILEGE_ESCALATION, 4),
    "AddUserToGroup": (PRIVILEGE_ESCALATION, 4),
    "RunInstances": (RESOURCE_ABUSE, 3),
    "CreateCluster": (RESOURCE_ABUSE, 3),
}

EVENT_SOURCE_ALIASES = {
    "monitoring": "cloudwatch",
}


def _service_prefix_from_event_source(event_source: str | None) -> str | None:
    if not event_source:
        return None

    prefix = event_source.split(".", 1)[0].lower()
    return EVENT_SOURCE_ALIASES.get(prefix, prefix)


def _taxonomy_key_candidates(event: ForensicEvent) -> list[str]:
    candidates: list[str] = []

    if ":" in event.api_action:
        candidates.append(event.api_action)
    else:
        service_prefix = _service_prefix_from_event_source(event.event_source)
        if service_prefix:
            candidates.append(f"{service_prefix}:{event.api_action}")
    suffix_matches = [
        key for key in AWS_API_TAXONOMY if key.endswith(f":{event.api_action}")
    ]
    if len(suffix_matches) == 1:
        candidates.append(suffix_matches[0])

    seen: set[str] = set()
    unique_candidates: list[str] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        unique_candidates.append(candidate)

    return unique_candidates


def _taxonomy_classification(event: ForensicEvent) -> tuple[str, int] | None:
    for candidate in _taxonomy_key_candidates(event):
        taxonomy_entry = AWS_API_TAXONOMY.get(candidate)
        if taxonomy_entry:
            return taxonomy_entry["category"], taxonomy_entry["severity"]
    return None


def _heuristic_classification(api_action: str) -> tuple[str, int]:
    for prefixes, classification in HEURISTIC_CLASSIFICATIONS:
        if api_action.startswith(prefixes):
            return classification
    return RECONNAISSANCE, 1


# ────────────────────────────────────────────────────────────────────────────
# GCP heuristics (dot-separated action suffix)
# ────────────────────────────────────────────────────────────────────────────
_GCP_SUFFIX_MAP: dict[str, tuple[str, int]] = {
    "list":          (RECONNAISSANCE, 1),
    "get":           (DATA_ACCESS, 2),
    "create":        (RESOURCE_ABUSE, 3),
    "insert":        (RESOURCE_ABUSE, 3),
    "update":        (RESOURCE_ABUSE, 3),
    "patch":         (RESOURCE_ABUSE, 3),
    "delete":        (RESOURCE_ABUSE, 3),
    "setIamPolicy":  (PRIVILEGE_ESCALATION, 4),
    "signJwt":       (PRIVILEGE_ESCALATION, 4),
    "signBlob":      (PRIVILEGE_ESCALATION, 4),
    "getAccessToken": (PRIVILEGE_ESCALATION, 4),
}


def _gcp_classify(event: ForensicEvent) -> tuple[str, int]:
    """Classify a GCP event: taxonomy first, then dot-suffix heuristic."""
    taxonomy_entry = GCP_API_TAXONOMY.get(event.api_action)
    if taxonomy_entry:
        return taxonomy_entry["category"], taxonomy_entry["severity"]

    # Heuristic: use the last dot-segment as the verb
    verb = event.api_action.rsplit(".", 1)[-1] if "." in event.api_action else event.api_action
    return _GCP_SUFFIX_MAP.get(verb, (RECONNAISSANCE, 1))


# ────────────────────────────────────────────────────────────────────────────
# Azure heuristics (operation suffix after last "/")
# ────────────────────────────────────────────────────────────────────────────
_AZURE_PRIV_ESC_PATTERNS = (
    "roleAssignments/write",
    "roleDefinitions/write",
    "policies/write",
    "elevateAccess/action",
)

_AZURE_SUFFIX_MAP: dict[str, tuple[str, int]] = {
    "read":   (RECONNAISSANCE, 1),
    "write":  (RESOURCE_ABUSE, 3),
    "delete": (RESOURCE_ABUSE, 3),
    "action": (RESOURCE_ABUSE, 3),
}


def _azure_classify(event: ForensicEvent) -> tuple[str, int]:
    """Classify an Azure event: taxonomy first, then suffix heuristics."""
    taxonomy_entry = AZURE_API_TAXONOMY.get(event.api_action)
    if taxonomy_entry:
        return taxonomy_entry["category"], taxonomy_entry["severity"]

    # Special privilege-escalation overrides (check before generic suffix)
    for pattern in _AZURE_PRIV_ESC_PATTERNS:
        if event.api_action.endswith(pattern):
            return PRIVILEGE_ESCALATION, 4

    # Heuristic: last path segment after "/"
    suffix = event.api_action.rsplit("/", 1)[-1].lower() if "/" in event.api_action else event.api_action
    return _AZURE_SUFFIX_MAP.get(suffix, (RECONNAISSANCE, 1))


# ────────────────────────────────────────────────────────────────────────────
# Stripe / Twilio heuristics (dot-separated `resource.action` names)
# ────────────────────────────────────────────────────────────────────────────
# Both taxonomies are exact-match tables, but the vendors emit far more event
# types than any table lists (Stripe alone has 200+). An unlisted type must not
# fall through to the AWS heuristic, which files every one of them as
# reconnaissance/1 — a `charge.dispute.closed` is not reconnaissance.

# Stripe resources whose events mean money moved or was set up to move.
_STRIPE_MONEY_PREFIXES = (
    "charge.", "payment_intent.", "payout.", "transfer.", "refund.",
    "invoice.", "checkout.", "subscription_schedule.", "topup.",
)


def _stripe_classify(event: ForensicEvent) -> tuple[str, int]:
    if event.event_source == "stripe-cli-request-log":
        if (event.api_action or "").startswith("GET "):
            return DATA_ACCESS, 2
        return RESOURCE_ABUSE, 2

    taxonomy_entry = STRIPE_API_TAXONOMY.get(event.api_action)
    if taxonomy_entry:
        return taxonomy_entry["category"], taxonomy_entry["severity"]

    if event.api_action.startswith(_STRIPE_MONEY_PREFIXES):
        return FINANCIAL_ABUSE, 2
    # The Events API records state changes only, so an unlisted event is still
    # a write against the account rather than a read.
    return RESOURCE_ABUSE, 2


def _twilio_classify(event: ForensicEvent) -> tuple[str, int]:
    taxonomy_entry = TWILIO_API_TAXONOMY.get(event.api_action)
    if taxonomy_entry:
        return taxonomy_entry["category"], taxonomy_entry["severity"]

    # The collector emits `message.<status>` / `call.<status>` and Twilio has
    # more statuses than the taxonomy lists (sending, accepted, ringing, …).
    if event.api_action.startswith("message."):
        return COMMUNICATION_ABUSE, 2
    if event.api_action.startswith("call."):
        return COMMUNICATION_ABUSE, 3
    return RECONNAISSANCE, 1


# ────────────────────────────────────────────────────────────────────────────
# Unified dispatch
# ────────────────────────────────────────────────────────────────────────────

def _classify_action(event: ForensicEvent) -> tuple[str, int]:
    if event.platform == "gcp":
        return _gcp_classify(event)
    if event.platform == "azure":
        return _azure_classify(event)
    if event.platform == "stripe":
        return _stripe_classify(event)
    if event.platform == "twilio":
        return _twilio_classify(event)

    # AWS (default)
    taxonomy_classification = _taxonomy_classification(event)
    if taxonomy_classification is not None:
        return taxonomy_classification

    classification = _heuristic_classification(event.api_action)
    return SPECIAL_OVERRIDES.get(event.api_action, classification)


def classify_event(event: ForensicEvent) -> ForensicEvent:
    """
    Assign impact_category and severity_weight to a single ForensicEvent.
    Returns the same event object (mutated in place) for chaining.
    """
    event.impact_category, event.severity_weight = _classify_action(event)
    return event


def classify_events(events: list[ForensicEvent]) -> list[ForensicEvent]:
    """Classify all events and apply bulk-access escalation."""
    for event in events:
        classify_event(event)

    # Outbound records have no source IP and are account activity, not proof of
    # a campaign or attribution to a particular credential. Flag their volume
    # without inventing an actor or changing their communication category.
    messages: dict[str, set[str]] = {}
    for event in events:
        raw = getattr(event, "raw_data", None)
        if (event.platform == "twilio" and event.api_action.startswith("message.")
                and isinstance(raw, dict) and raw.get("sid") and raw.get("direction", "").startswith("outbound")):
            messages.setdefault(str(getattr(event, "principal_id", "") or ""), set()).add(str(raw["sid"]))
    for event in events:
        if (event.platform == "twilio" and event.impact_category == COMMUNICATION_ABUSE
                and event.api_action.startswith("message.")
                and len(messages.get(str(getattr(event, "principal_id", "") or ""), set())) >= TWILIO_BULK_THRESHOLD):
            event.severity_weight = 4

    counts = Counter(
        (event.api_action, event.source_ip)
        for event in events
        if event.source_ip
    )

    for event in events:
        key = (event.api_action, event.source_ip)
        if (
            event.source_ip
            and event.impact_category == DATA_ACCESS
            and counts[key] >= _bulk_threshold(event.platform)
        ):
            event.impact_category = DATA_EXFILTRATION
            event.severity_weight = 4

    return events


def classify_all_events(incident_id: str, db: Session) -> list[ORMForensicEvent]:
    """
    Load one incident's stored events, classify them in place, persist the
    classifier output, and return the updated ORM event rows.
    """
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    events = incident.events
    if not events:
        return events

    # Classify the two periods separately so older activity cannot inflate
    # bulk-access escalation during the exposure window.
    from normalizer.time_window import after_exposure
    current = after_exposure(events, incident.exposure_start)
    current_ids = {event.event_id for event in current}
    classify_events([event for event in events if event.event_id not in current_ids])
    classify_events(current)
    db.commit()
    # Refresh events so that returned ORM instances are not expired after commit.
    for event in events:
        db.refresh(event)

    return events

