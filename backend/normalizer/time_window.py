"""Separate provider history from activity after detected exposure."""
from datetime import datetime, timezone


def utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def after_exposure(events, exposure_start: datetime):
    start = utc(exposure_start)
    return [event for event in events if isinstance(getattr(event, 'timestamp', None), datetime)
            and utc(event.timestamp) >= start]


def within_exposure(events, exposure_start: datetime, exposure_end: datetime | None = None):
    observed = after_exposure(events, exposure_start)
    return [event for event in observed if utc(event.timestamp) <= utc(exposure_end)] if exposure_end else observed
