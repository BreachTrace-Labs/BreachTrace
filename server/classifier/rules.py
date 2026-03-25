"""
Rule-based impact classifier for forensic events.
Uses exact taxonomy lookup, then prefix heuristics, then fallback.
"""

from collections import Counter

from classifier.taxonomy_aws import CATEGORY_RULES
from normalizer.schema import ForensicEvent


def classify_event(event: ForensicEvent) -> tuple[str, int]:
    """
    Classify a single ForensicEvent.
    Returns (impact_category, severity_weight).
    """
    action = event.api_action

    # Step 1: Exact lookup
    if action in CATEGORY_RULES:
        return CATEGORY_RULES[action]

    # Step 2: Privilege escalation overrides (always weight 4)
    privilege_actions = {
        "CreateAccessKey", "AttachUserPolicy", "AddUserToGroup",
        "PutRolePolicy", "PutUserPolicy", "AttachRolePolicy",
    }
    if action in privilege_actions:
        return ("privilege_escalation", 4)

    # Step 3: Resource abuse overrides
    if action in ("RunInstances", "CreateCluster"):
        return ("resource_abuse", 3)

    # Step 4: Prefix heuristics
    if action.startswith(("List", "Describe", "Get")) and action.startswith(("List", "Describe")):
        return ("reconnaissance", 1)
    if action.startswith("Get"):
        return ("data_access", 2)
    if action.startswith(("Put", "Create")):
        return ("resource_abuse", 3)
    if action.startswith("Delete"):
        return ("resource_abuse", 3)

    # Step 5: Fallback
    return ("reconnaissance", 1)


def classify_all_events(events: list[ForensicEvent]) -> list[ForensicEvent]:
    """
    Classify all events and apply bulk detection escalation.
    Modifies events in place and returns them.
    """
    # First pass: classify each event
    for event in events:
        category, weight = classify_event(event)
        event.impact_category = category
        event.severity_weight = weight

    # Second pass: bulk detection escalation
    # If same api_action called 5+ times from same source_ip → exfiltration
    ip_action_counts: Counter[tuple[str | None, str]] = Counter()
    for event in events:
        ip_action_counts[(event.source_ip, event.api_action)] += 1

    for event in events:
        key = (event.source_ip, event.api_action)
        if (
            ip_action_counts[key] >= 5
            and event.impact_category == "data_access"
        ):
            event.impact_category = "exfiltration"
            event.severity_weight = 4

    return events
