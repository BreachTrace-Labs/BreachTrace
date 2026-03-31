"""
pipeline.py — Background forensic-collection and intelligence orchestrator.

After credential detection creates an IncidentRecord, the pipeline runs as a
FastAPI BackgroundTask (non-blocking) and executes all five stages:

  1. Queries AWS CloudTrail for activity during the exposure window.
  2. Persists each ForensicEvent to the database.
  3. Classifies every event (impact_category + severity_weight).
  4. Scores the incident (overall severity, GDPR flag, financial impact).
  5. Generates a Gemini forensic report + remediation checklist.

Status transitions: collecting → classifying → scoring → reporting → complete
Each stage is timed; a warning is logged if total pipeline exceeds 60 seconds.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from classifier.rules import classify_all_events
from collectors.aws import AWSCloudTrailCollector
from db.crud import (
    save_collection_status,
    save_forensic_events,
    update_status,
)
from db.database import SessionLocal
from db.models import IncidentRecord
from reporter.gemini import generate_report
from scorer.severity import check_gdpr_flag, compute_financial_impact, score_incident

logger = logging.getLogger(__name__)

# Map human-readable severity labels → DB integer (1–4)
_SEVERITY_TO_INT: dict[str, int] = {
    "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
    "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _extract_remediation_steps(report_text: str) -> list[str]:
    """
    Parse ☐-prefixed checklist items from the Gemini report.

    Falls back to numbered list items (``1) …`` / ``1. …``) when the report
    does not use the checkbox format.
    """
    steps: list[str] = []
    for line in report_text.split("\n"):
        stripped = line.strip()
        if "☐" in stripped:
            idx = stripped.index("☐")
            step = stripped[idx:].strip()
            if step:
                steps.append(step)

    if not steps:
        # Fallback: numbered items like "1) Rotate the key" or "1. Rotate…"
        for line in report_text.split("\n"):
            stripped = line.strip()
            if re.match(r"^\d+[.)]\s+", stripped):
                steps.append(stripped)

    return steps


def run_collection_pipeline(incident_id: str, access_key_id: str, exposure_start: datetime) -> None:
    """
    Execute the full forensic pipeline for a single incident.

    Runs inside a FastAPI ``BackgroundTask`` — does **not** block the HTTP
    response.  Opens its own DB session.

    Stages and status transitions
    ------------------------------
    collecting  → (CloudTrail lookup + persist events)
    classifying → (rule-based event classification)
    scoring     → (severity score + GDPR flag + financial impact)
    reporting   → (Gemini report generation)
    complete

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
    pipeline_start = time.monotonic()
    try:
        # The exposure may still be open — use now() as end_time.
        exposure_end = datetime.now(tz=timezone.utc)

        logger.info(
            "Pipeline started for incident %s (key=%s)",
            incident_id,
            access_key_id,
        )

        # ── STAGE 1: Collect CloudTrail events ────────────────────────────
        t0 = time.monotonic()
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

        logger.info(
            "Stage 1 (collect): %d events in %.1fs",
            len(events),
            time.monotonic() - t0,
        )

        # ── STAGE 2: Persist events ────────────────────────────────────────
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

        update_status(db, incident_id, "classifying")

        # ── STAGE 3: Classify events ───────────────────────────────────────
        t0 = time.monotonic()
        try:
            classified_events = classify_all_events(incident_id, db)
        except Exception:
            logger.exception("Classification failed for incident %s", incident_id)
            update_status(db, incident_id, "error")
            return

        logger.info(
            "Stage 3 (classify): %d events in %.1fs",
            len(classified_events),
            time.monotonic() - t0,
        )
        update_status(db, incident_id, "scoring")

        # ── STAGE 4: Score incident ────────────────────────────────────────
        # score_incident / check_gdpr_flag / compute_financial_impact all work
        # with duck-typed ForensicEvent-like objects; ORM rows satisfy the
        # required attribute contract.
        t0 = time.monotonic()
        try:
            overall_severity = score_incident(classified_events)
            financial_impact = compute_financial_impact(classified_events)
            gdpr_flag = check_gdpr_flag(classified_events)

            incident_record: IncidentRecord | None = db.get(IncidentRecord, incident_id)
            if incident_record is not None:
                incident_record.overall_severity = _SEVERITY_TO_INT.get(overall_severity, 1)
                incident_record.financial_impact = financial_impact
                incident_record.gdpr_flag = gdpr_flag
                db.commit()
        except Exception:
            logger.exception("Scoring failed for incident %s", incident_id)
            update_status(db, incident_id, "error")
            return

        logger.info(
            "Stage 4 (score): severity=%s gdpr=%s in %.1fs",
            overall_severity,
            gdpr_flag,
            time.monotonic() - t0,
        )
        update_status(db, incident_id, "reporting")

        # ── STAGE 5: Generate Gemini report ───────────────────────────────
        t0 = time.monotonic()
        try:
            incident_record = db.get(IncidentRecord, incident_id)
            if incident_record is None:
                logger.error("Incident %s disappeared before report stage", incident_id)
                return

            # Exposure duration (seconds); exposure_end may still be None.
            exp_start = incident_record.exposure_start
            exp_end = incident_record.exposure_end or datetime.now(tz=timezone.utc)
            # Ensure both are timezone-aware before subtraction.
            if exp_start.tzinfo is None:
                exp_start = exp_start.replace(tzinfo=timezone.utc)
            if exp_end.tzinfo is None:
                exp_end = exp_end.replace(tzinfo=timezone.utc)
            exposure_duration_s = max(0, int((exp_end - exp_start).total_seconds()))

            affected_resources = sorted(
                {e.affected_resource for e in classified_events if e.affected_resource}
            )
            source_ips = sorted(
                {e.source_ip for e in classified_events if e.source_ip}
            )

            report_text = generate_report(
                events=classified_events,
                overall_severity=overall_severity,
                exposure_duration_seconds=exposure_duration_s,
                affected_resources=affected_resources,
                source_ips=source_ips,
            )
            remediation_steps = _extract_remediation_steps(report_text)

            incident_record.report_text = report_text
            incident_record.remediation_steps = remediation_steps
            db.commit()
        except Exception:
            logger.exception("Report generation failed for incident %s", incident_id)
            update_status(db, incident_id, "error")
            return

        logger.info(
            "Stage 5 (report): %d remediation steps in %.1fs",
            len(remediation_steps),
            time.monotonic() - t0,
        )

        update_status(db, incident_id, "complete")

        total_elapsed = time.monotonic() - pipeline_start
        if total_elapsed > 60:
            logger.warning(
                "Pipeline exceeded 60s target for incident %s: %.1fs",
                incident_id,
                total_elapsed,
            )
        else:
            logger.info(
                "Pipeline complete for incident %s — %.1fs (target: 60s)",
                incident_id,
                total_elapsed,
            )

    except Exception:
        logger.exception("Unexpected error in pipeline for %s", incident_id)
        try:
            update_status(db, incident_id, "error")
        except Exception:
            logger.exception("Failed to set error status for %s", incident_id)
    finally:
        db.close()
