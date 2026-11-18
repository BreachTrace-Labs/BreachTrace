"""
pipeline.py — Background forensic-collection and intelligence orchestrator.

After credential detection creates an IncidentRecord, the pipeline runs as a
FastAPI BackgroundTask (non-blocking) and executes all five stages:

  1. Queries AWS CloudTrail for activity during the exposure window.
  2. Persists each ForensicEvent to the database.
  3. Classifies every event (impact_category + severity_weight).
  4. Scores the incident (overall severity, GDPR flag, financial impact).
  5. Writes the report from verified facts (template first; the local report
     model may upgrade the prose once the incident is complete).

Status transitions: collecting → classifying → scoring → reporting → complete
Each stage is timed; a warning is logged if total pipeline exceeds 60 seconds.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from classifier.rules import classify_all_events
from collection_credentials import ReaderConfigurationError, project_reader
from collectors.aws import AWSCloudTrailCollector
from collectors.azure import AzureActivityLogCollector
from collectors.gcp import GCPAuditLogCollector
from collectors.stripe import StripeEventsCollector
from collectors.twilio import TwilioUsageCollector
from db.crud import (
    reset_incident_for_refresh,
    save_collection_status,
    save_forensic_events,
    update_status,
)
from db.database import SessionLocal
from db.models import IncidentRecord
from normalizer.time_window import after_exposure
from rag.index import index_incident
from reporter.compose import deterministic_sections, render_report
from reporter.facts import build_fact_sheet
from reporter.writers import upgrade_report
from scorer.severity import (
    check_gdpr_flag,
    check_pcidss_flag,
    compute_financial_impact,
    score_incident,
)

logger = logging.getLogger(__name__)

# Collector dispatch map — keyed by platform string
# Tier 1 platforms only. A platform absent here has no queryable audit log, and
# the pipeline must not attempt collection for it — see _TIER_TWO_PLATFORMS.
# Firebase is intentionally missing: firebase_service_account maps to the "gcp"
# platform in CREDENTIAL_TYPE_TO_PLATFORM and collects through GCPAuditLogCollector.
_COLLECTOR_MAP = {
    "aws": AWSCloudTrailCollector,
    "gcp": GCPAuditLogCollector,
    "azure": AzureActivityLogCollector,
    "stripe": StripeEventsCollector,
    "twilio": TwilioUsageCollector,
}

# Query recent provider history through collection time, subject to each
# provider's retention, access and collector limits.
_COLLECTION_HISTORY_DAYS = 30

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


def _index_incident_safely(db: Session, incident_id: str) -> None:
    try:
        index_incident(db, incident_id)
    except Exception:
        db.rollback()
        logger.exception("Search indexing failed for incident %s", incident_id)


def _upgrade_report(db: Session, incident_id: str, facts: dict) -> bool:
    """
    Replace the template prose with a model-written version if one validates.

    The remediation checklist is built in code and identical in both versions,
    so remediation_steps is left as is.
    """
    t0 = time.monotonic()
    try:
        upgraded = upgrade_report(facts)
    except Exception:
        logger.exception("Report upgrade failed for incident %s", incident_id)
        return False
    if upgraded is None:
        return False

    report_text, source = upgraded
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        return False
    incident.report_text = report_text
    incident.report_source = source
    db.commit()
    logger.info(
        "Report for incident %s upgraded by %s in %.1fs", incident_id, source, time.monotonic() - t0
    )
    return True


def run_collection_pipeline(
    incident_id: str,
    credential: str,
    exposure_start: datetime,
    *,
    platform: str = "aws",
    refresh_existing: bool = False,
) -> None:
    """
    Execute the full forensic pipeline for a single incident.

    Runs inside a FastAPI ``BackgroundTask`` — does **not** block the HTTP
    response.  Opens its own DB session.

    Stages and status transitions
    ------------------------------
    collecting  → (platform event lookup + persist events)
    classifying → (rule-based event classification)
    scoring     → (severity score + GDPR flag + financial impact)
    reporting   → (Gemini report generation)
    complete

    Parameters
    ----------
    incident_id : str
        UUID of the IncidentRecord just created.
    credential : str
        The leaked credential identifier: AKIA key (AWS), service account
        email (GCP), or client_id (Azure).
    exposure_start : datetime
        Beginning of the exposure window (commit timestamp).
    platform : str
        One of 'aws', 'gcp', 'azure'.  Selects the event collector.
    """
    db: Session = SessionLocal()
    pipeline_start = time.monotonic()
    try:
        if refresh_existing:
            incident = reset_incident_for_refresh(db, incident_id)
            if incident is None:
                logger.warning("Refresh requested for missing incident %s", incident_id)
                return

        # The exposure may still be open — use now() as end_time.
        exposure_end = datetime.now(tz=timezone.utc)

        logger.info(
            "%s pipeline started for incident %s (platform=%s)",
            "Refresh" if refresh_existing else "Collection",
            incident_id,
            platform,
        )

        # ── STAGE 1: Collect events ────────────────────────────────────────
        # Provider history supplies context from before detected exposure.
        if exposure_start.tzinfo is None:
            exposure_start = exposure_start.replace(tzinfo=timezone.utc)
        exposure_start = exposure_start.astimezone(timezone.utc)
        collection_start = exposure_end - timedelta(days=_COLLECTION_HISTORY_DAYS)

        collector_cls = _COLLECTOR_MAP.get(platform)
        if collector_cls is None:
            logger.error(
                "Unknown platform '%s' for incident %s — aborting pipeline",
                platform,
                incident_id,
            )
            save_collection_status(
                db,
                incident_id=incident_id,
                platform=platform,
                status="error",
                event_count=0,
                error_message=f"Unsupported platform: {platform}",
            )
            update_status(db, incident_id, "error")
            return

        t0 = time.monotonic()
        try:
            incident = db.get(IncidentRecord, incident_id)
            if incident is None:
                logger.warning("Incident %s disappeared before collection", incident_id)
                return
            reader = project_reader(db, incident, platform)
            if reader is None:
                collector = collector_cls()
            elif platform == 'stripe':
                collector = collector_cls(api_key=reader['api_key'])
                # A wallet reader must be used even if the detected key is still
                # in memory. Preserve the mode prefix without passing the secret.
                credential = incident.credential_hint or ''
            else:
                collector = collector_cls(reader=reader)
            events = collector.collect(
                credential=credential,
                start_time=collection_start,
                end_time=exposure_end,
            )
        except Exception as exc:
            if isinstance(exc, ReaderConfigurationError):
                error_message = str(exc)
            elif platform == "stripe":
                # Provider exceptions can include request data or credentials.
                if isinstance(exc, ModuleNotFoundError) and exc.name == "stripe":
                    error_message = "The Stripe SDK is not installed in the backend environment."
                elif type(exc).__name__ == "AuthenticationError":
                    provider_message = str(getattr(exc, "user_message", "") or "").lower()
                    if "expired api key" in provider_message:
                        key_label = "configured Stripe reader key" if refresh_existing else "detected Stripe key"
                        error_message = (
                            f"The {key_label} has expired. Configure an active "
                            "Events reader for the same account and test/live mode, then refresh."
                        )
                    else:
                        error_message = (
                            "Stripe rejected authentication (HTTP 401). Check that the key is active "
                            "and copied correctly. Configure a valid reader "
                            "for the same account and test/live mode."
                        )
                elif type(exc).__name__ == "PermissionError":
                    error_message = (
                        "Stripe accepted the key but denied Events access. Configure an Events "
                        "reader for the same account and test/live mode, then refresh."
                    )
                elif isinstance(exc, ValueError):
                    error_message = str(exc) if str(exc).startswith(("No Stripe API key", "Configured Stripe key mode", "Stripe event limit", "Stripe pagination", "Stripe event is missing")) else "Stripe returned invalid event data."
                else:
                    error_message = "Stripe event collection failed. Check provider access and backend logs."
                logger.warning("Stripe collection failed for incident %s (%s)", incident_id, type(exc).__name__)
            elif platform == "azure":
                status_code = getattr(exc, 'status_code', None)
                if status_code in (401, 403) or type(exc).__name__ in ('ClientAuthenticationError', 'CredentialUnavailableError'):
                    error_message = ('Azure authentication or Activity Log access failed. Check the configured reader '
                                     'credentials and subscription permissions, then refresh.')
                elif isinstance(exc, ValueError) and str(exc).startswith('Azure Activity Log collection limit'):
                    error_message = str(exc)
                else:
                    error_message = 'Azure Activity Log collection failed. Check provider access and backend logs.'
                logger.warning("Azure collection failed for incident %s (%s)", incident_id, type(exc).__name__)
            else:
                logger.warning("%s event collection failed for incident %s (%s)", platform.upper(), incident_id, type(exc).__name__)
                error_message = f"{platform.upper()} event collection failed after retries"
            save_collection_status(
                db,
                incident_id=incident_id,
                platform=platform,
                status="error",
                event_count=0,
                error_message=error_message,
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
                platform=platform,
                status="success",
                event_count=len(events),
            )
        else:
            save_collection_status(
                db,
                incident_id=incident_id,
                platform=platform,
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
        exposure_events = after_exposure(classified_events, exposure_start)
        update_status(db, incident_id, "scoring")

        # ── STAGE 4: Score incident ────────────────────────────────────────
        # score_incident / check_gdpr_flag / compute_financial_impact all work
        # with duck-typed ForensicEvent-like objects; ORM rows satisfy the
        # required attribute contract.
        t0 = time.monotonic()
        try:
            overall_severity = score_incident(exposure_events)
            financial_impact = compute_financial_impact(exposure_events)
            # gdpr_flag covers both GDPR and PCI-DSS — either triggers the flag
            gdpr_flag = check_gdpr_flag(exposure_events) or check_pcidss_flag(exposure_events)

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

        # ── STAGE 5: Report (template now, model upgrade after completion) ─
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

            # Facts are computed once; every writer works from the same sheet.
            facts = build_fact_sheet(
                exposure_events,
                platform=platform,
                overall_severity=overall_severity,
                exposure_duration_seconds=exposure_duration_s,
                credential_type=incident_record.credential_type,
                credential_hint=incident_record.credential_hint,
            )
            # The template report lands immediately, so the incident completes
            # within the 60s target on any machine. A model may upgrade the
            # prose afterwards (see _upgrade_report).
            report_text = render_report(facts, deterministic_sections(facts))
            remediation_steps = _extract_remediation_steps(report_text)

            incident_record.report_text = report_text
            incident_record.report_source = "deterministic"
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


        # ── After completion: search index + optional model-written prose ──
        # Outside the timed stages on purpose: neither may delay or fail the
        # incident, which is already complete with a grounded report.
        _index_incident_safely(db, incident_id)
        if _upgrade_report(db, incident_id, facts):
            _index_incident_safely(db, incident_id)

    except Exception:
        logger.exception("Unexpected error in pipeline for %s", incident_id)
        try:
            update_status(db, incident_id, "error")
        except Exception:
            logger.exception("Failed to set error status for %s", incident_id)
    finally:
        db.close()
