from collections import Counter

from normalizer.schema import ForensicEvent
from classifier.taxonomy_aws import AWS_ACTION_TAXONOMY, SEVERITY_WEIGHTS, DATA_EXFILTRATION, DATA_ACCESS

BULK_THRESHOLD = 5  # same api_action + same IP ≥ 5 times → escalate to exfiltration


def classify_event(event: ForensicEvent) -> ForensicEvent:
    """
    Assign impact_category and severity_weight to a single ForensicEvent.
    Returns the same event object (mutated in place) for chaining.
    TODO (Yash/Day 4): implement bulk-detection escalation logic.
    """
    category = AWS_ACTION_TAXONOMY.get(event.api_action)
    event.impact_category = category
    event.severity_weight = SEVERITY_WEIGHTS.get(category) if category else None
    return event


def classify_events(events: list[ForensicEvent]) -> list[ForensicEvent]:
    """Classify all events and apply bulk-access escalation."""
    for event in events:
        classify_event(event)

    # Bulk escalation: data_access → data_exfiltration if same action+IP ≥ threshold
    counts = Counter((e.api_action, e.source_ip) for e in events)
    for event in events:
        key = (event.api_action, event.source_ip)
        if event.impact_category == DATA_ACCESS and counts[key] >= BULK_THRESHOLD:
            event.impact_category = DATA_EXFILTRATION
            event.severity_weight = SEVERITY_WEIGHTS[DATA_EXFILTRATION]

    return events
