from __future__ import annotations

from collections import Counter

from classifier.taxonomy_aws import AWS_API_TAXONOMY
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


def _service_prefix_from_event_source(event_source: str | None) -> str | None:
    if not event_source:
        return None

    prefix = event_source.split(".", 1)[0].lower()
    return EVENT_SOURCE_ALIASES.get(prefix, prefix)


def _taxonomy_key_candidates(event: ForensicEvent) -> list[str]:
    candidates: list[str] = []

    if ":" in event.api_action:
        candidates.append(event.api_action)

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


def _classify_action(event: ForensicEvent) -> tuple[str, int]:
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
            and counts[key] >= BULK_THRESHOLD
        ):
            event.impact_category = DATA_EXFILTRATION
            event.severity_weight = 4

    return events

