"""Summarise observed activity since exposure; not a permissions inventory."""
from collections import Counter
from datetime import datetime

from normalizer.time_window import within_exposure, utc
from scorer.severity import score_incident


def dynamic_blast_radius(events, exposure_start: datetime, *, forensic_tier: int, incident_status: str, collection_status: str | None, exposure_end: datetime | None = None):
    observed = within_exposure(events, exposure_start, exposure_end)
    # Unsuccessful events do not establish a successfully exercised action.
    successful = [event for event in observed if event.success is True]
    failed = [event for event in observed if event.success is False]
    classified = [event for event in successful if event.impact_category and event.severity_weight is not None]
    platforms = []
    for platform in sorted({event.platform or 'unknown' for event in observed}):
        group = [event for event in observed if (event.platform or 'unknown') == platform]
        successes = [event for event in group if event.success is True]
        categories = Counter(event.impact_category or 'unclassified' for event in successes)
        platforms.append({
            'platform': platform,
            'event_count': len(group),
            'successful_count': len(successes),
            'failed_count': sum(event.success is False for event in group),
            'resource_count': len({event.affected_resource for event in successes if event.affected_resource}),
            'categories': [{'category': category, 'count': count} for category, count in sorted(categories.items())],
            'actions': [{'action': action, 'count': count} for action, count in sorted(Counter(event.api_action for event in successes if event.api_action).items())],
        })
    if forensic_tier == 2:
        status = 'unavailable'
    elif incident_status in {'detecting', 'collecting', 'classifying', 'scoring', 'reporting'}:
        status = 'collecting'
    elif incident_status == 'error' or collection_status == 'error':
        status = 'error'
    elif observed:
        status = 'observed'
    elif collection_status in {'success', 'no_activity'}:
        status = 'no_observed_activity'
    else:
        status = 'unavailable'
    timestamps = [utc(event.timestamp) for event in observed]
    return {
        'status': status,
        'severity': score_incident(classified).upper() if classified and forensic_tier != 2 else None,
        'event_count': len(observed), 'successful_count': len(successful), 'failed_count': len(failed),
        'resource_count': len({(event.platform, event.affected_resource) for event in successful if event.affected_resource}),
        'last_observed_at': max(timestamps) if timestamps else None,
        'platforms': platforms,
    }
