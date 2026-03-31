"""
pipeline.py — Background forensic-collection orchestrator.

After credential detection creates an IncidentRecord, the pipeline runs as a
FastAPI BackgroundTask (non-blocking) and:

  1. Queries AWS CloudTrail for activity during the exposure window.
  2. Persists each ForensicEvent to the database.
  3. Records the CollectionStatus result.
  4. Updates the incident status to 'classifying' (ready for the Day-4 chain).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from collectors.aws import AWSCloudTrailCollector
from db.crud import (
    save_collection_status,
    save_forensic_events,
    update_status,
)
from db.database import SessionLocal

logger = logging.getLogger(__name__)


def run_collection_pipeline(incident_id: str, access_key_id: str, exposure_start: datetime) -> None:
    """
    Execute the forensic collection pipeline for a single incident.

    Designed to run inside a FastAPI ``BackgroundTask`` so it does **not**
    block the HTTP response.  Opens its own DB session.

    Parameters
    ----------
    incident_id : str
        UUID of the IncidentRecord just created.
    access_key_id : str
        The leaked AKIA… key ID passed to CloudTrail ``LookupEvents``.
    exposure_start : datetime
        Beginning of the exposure window (commit timestamp).
    """
    db: Session = SessionLocal()
    try:
        # The exposure may still be open — use now() as end_time.
        exposure_end = datetime.now(tz=timezone.utc)

        logger.info(
            "Collection pipeline started for incident %s (key=%s)",
            incident_id,
            access_key_id,
        )

        # 1. Collect CloudTrail events ─────────────────────────────────────
        collector = AWSCloudTrailCollector()
        try:
            events = collector.collect(
                credential=access_key_id,
                start_time=exposure_start,
                end_time=exposure_end,
            )
        except Exception:
            logger.exception(
                "CloudTrail collection failed for incident %s", incident_id
            )
            save_collection_status(
                db,
                incident_id=incident_id,
                platform="aws",
                status="error",
                event_count=0,
                error_message="CloudTrail lookup_events failed after retries",
            )
            update_status(db, incident_id, "error")
            return

        # 2. Persist events ────────────────────────────────────────────────
        if events:
            save_forensic_events(db, incident_id, events)
            save_collection_status(
                db,
                incident_id=incident_id,
                platform="aws",
                status="success",
                event_count=len(events),
            )
        else:
            save_collection_status(
                db,
                incident_id=incident_id,
                platform="aws",
                status="no_activity",
                event_count=0,
            )

        # 3. Advance incident status ───────────────────────────────────────
        update_status(db, incident_id, "classifying")
        logger.info(
            "Collection pipeline complete for incident %s — %d events stored",
            incident_id,
            len(events),
        )

    except Exception:
        logger.exception("Unexpected error in collection pipeline for %s", incident_id)
        try:
            update_status(db, incident_id, "error")
        except Exception:
            logger.exception("Failed to set error status for %s", incident_id)
    finally:
        db.close()
