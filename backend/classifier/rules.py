from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from classifier.taxonomy_aws import AWS_API_TAXONOMY
from classifier.taxonomy_azure import AZURE_API_TAXONOMY
from classifier.taxonomy_gcp import GCP_API_TAXONOMY
from db.models import ForensicEvent as ORMForensicEvent
from db.models import IncidentRecord
from normalizer.schema import ForensicEvent

RECONNAISSANCE = "reconnaissance"
DATA_ACCESS = "data_access"
DATA_EXFILTRATION = "exfiltration"
RESOURCE_ABUSE = "resource_abuse"
PRIVILEGE_ESCALATION = "privilege_escalation"

BULK_THRESHOLD = 5  # same api_action + same IP >= 5 times -> escalate to exfiltration

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


_TAXONOMY_MAP: dict[str, dict[str, dict]] = {
    "aws": AWS_API_TAXONOMY,
    "gcp": GCP_API_TAXONOMY,
    "azure": AZURE_API_TAXONOMY,
}


def _get_taxonomy(platform: str | None) -> dict[str, dict]:
    if not platform:
        return AWS_API_TAXONOMY
    return _TAXONOMY_MAP.get(platform.lower(), AWS_API_TAXONOMY)


def _service_prefix_from_event_source(event_source: str | None) -> str | None:
    if not event_source:
        return None

    prefix = event_source.split(".", 1)[0].lower()
    return EVENT_SOURCE_ALIASES.get(prefix, prefix)


def _taxonomy_key_candidates(
    event: ForensicEvent,
    *,
    taxonomy: dict[str, dict],
) -> list[str]:
    candidates: list[str] = []

    if ":" in event.api_action:
        candidates.append(event.api_action)
    else:
        service_prefix = _service_prefix_from_event_source(event.event_source)
        if service_prefix:
            candidates.append(f"{service_prefix}:{event.api_action}")
    suffix_matches = [key for key in taxonomy if key.endswith(f":{event.api_action}")]
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


def _aws_taxonomy_classification(event: ForensicEvent) -> tuple[str, int] | None:
    for candidate in _taxonomy_key_candidates(event, taxonomy=AWS_API_TAXONOMY):
        taxonomy_entry = AWS_API_TAXONOMY.get(candidate)
        if taxonomy_entry:
            return taxonomy_entry["category"], taxonomy_entry["severity"]
    return None


def _taxonomy_classification(event: ForensicEvent) -> tuple[str, int] | None:
    platform = (event.platform or "aws").lower()
    taxonomy = _get_taxonomy(platform)

    # AWS needs candidate expansion because events may store api_action without
    # the "service:" prefix, or may only provide event_source.
    if platform == "aws":
        return _aws_taxonomy_classification(event)

    # For GCP and Azure we store method/operation names directly.
    taxonomy_entry = taxonomy.get(event.api_action)
    if taxonomy_entry:
        return taxonomy_entry["category"], taxonomy_entry["severity"]
    return None


GCP_HEURISTIC_PREFIXES: dict[str, tuple[str, int]] = {
    "list": (RECONNAISSANCE, 1),
    "get": (DATA_ACCESS, 2),
    "create": (RESOURCE_ABUSE, 3),
    "delete": (RESOURCE_ABUSE, 3),
    "update": (RESOURCE_ABUSE, 3),
    "setIamPolicy": (PRIVILEGE_ESCALATION, 4),
    "signJwt": (PRIVILEGE_ESCALATION, 4),
}


AZURE_HEURISTIC_SUFFIXES: dict[str, tuple[str, int]] = {
    "/read": (RECONNAISSANCE, 1),
    "/write": (RESOURCE_ABUSE, 3),
    "/delete": (RESOURCE_ABUSE, 3),
    "/action": (RESOURCE_ABUSE, 3),
}


AZURE_PRIV_ESC_PATTERNS: tuple[str, ...] = (
    "roleAssignments/write",
    "roleDefinitions/write",
    "policies/write",
)


def _aws_heuristic_classification(api_action: str) -> tuple[str, int]:
    for prefixes, classification in HEURISTIC_CLASSIFICATIONS:
        if api_action.startswith(prefixes):
            return classification
    return RECONNAISSANCE, 1


def _gcp_heuristic_classification(api_action: str) -> tuple[str, int]:
    # Cloud Audit Logs method names are dot-separated. We classify based on
    # the last segment (verb), not the full string.
    verb = api_action.rsplit(".", 1)[-1]
    return GCP_HEURISTIC_PREFIXES.get(verb, (RECONNAISSANCE, 1))


def _azure_heuristic_classification(operation: str) -> tuple[str, int]:
    op = operation or ""
    for pattern in AZURE_PRIV_ESC_PATTERNS:
        if pattern in op:
            return PRIVILEGE_ESCALATION, 4

    for suffix, classification in AZURE_HEURISTIC_SUFFIXES.items():
        if op.endswith(suffix):
            return classification
    return RECONNAISSANCE, 1


def _heuristic_classification(platform: str, api_action: str) -> tuple[str, int]:
    if platform == "gcp":
        return _gcp_heuristic_classification(api_action)
    if platform == "azure":
        return _azure_heuristic_classification(api_action)
    return _aws_heuristic_classification(api_action)


def _classify_action(event: ForensicEvent) -> tuple[str, int]:
    taxonomy_classification = _taxonomy_classification(event)
    if taxonomy_classification is not None:
        return taxonomy_classification

    platform = (event.platform or "aws").lower()
    classification = _heuristic_classification(platform, event.api_action)
    if platform == "aws":
        return SPECIAL_OVERRIDES.get(event.api_action, classification)
    return classification


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

    counts: Counter[tuple[str, str]] = Counter()
    for e in events:
        if e.source_ip is None:
            continue
        counts[(e.api_action, e.source_ip)] += 1

    for event in events:
        if event.source_ip is None:
            continue

        key = (event.api_action, event.source_ip)
        if (
            event.impact_category == DATA_ACCESS
            and counts[key] >= BULK_THRESHOLD
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

    classify_events(events)
    db.commit()
    # Refresh events so that returned ORM instances are not expired after commit.
    for event in events:
        db.refresh(event)

    return events

