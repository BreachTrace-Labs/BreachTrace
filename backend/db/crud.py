"""CRUD helpers — thin wrappers over SQLAlchemy ORM used by route handlers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.orm import Session

from db.models import CollectionStatus, IncidentRecord
from db.models import ForensicEvent as ORMForensicEvent
from normalizer.schema import ForensicEvent as PydanticForensicEvent


# ---------------------------------------------------------------------------
# Incident helpers
# ---------------------------------------------------------------------------

def create_incident(
    db: Session,
    *,
    credential_type: str,
    credential_hint: str,
    access_key_id: str | None = None,
    repo_url: str,
    commit_hash: str,
    exposure_start: datetime,
    principal_id: str | None = None,
    gcp_project_id: str | None = None,
    azure_tenant_id: str | None = None,
    azure_subscription_id: str | None = None,
    forensic_tier: int = 1,
    unavailable_reason: str | None = None,
    project_id: str | None = None,
) -> IncidentRecord:
    """Insert a new incident row and return the persisted object."""
    incident = IncidentRecord(
        incident_id=str(uuid.uuid4()),
        project_id=project_id,
        credential_type=credential_type,
        credential_hint=credential_hint,
        access_key_id=access_key_id,
        repo_url=repo_url,
        commit_hash=commit_hash,
        exposure_start=exposure_start,
        principal_id=principal_id,
        forensic_tier=forensic_tier,
        unavailable_reason=unavailable_reason,
        gcp_project_id=gcp_project_id,
        azure_tenant_id=azure_tenant_id,
        azure_subscription_id=azure_subscription_id,
        status="collecting",
        remediation_steps=[],
        gdpr_flag=False,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def get_incident(db: Session, incident_id: str) -> IncidentRecord | None:
    return db.get(IncidentRecord, incident_id)


def list_incidents(
    db: Session,
    *,
    limit: int = 50,
    offset: int = 0,
) -> Sequence[IncidentRecord]:
    return (
        db.query(IncidentRecord)
        .order_by(IncidentRecord.exposure_start.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def update_status(db: Session, incident_id: str, status: str) -> None:
    incident = db.get(IncidentRecord, incident_id)
    if incident:
        incident.status = status
        db.commit()


def set_exposure_end(db: Session, incident_id: str, end_time: datetime) -> None:
    incident = db.get(IncidentRecord, incident_id)
    if incident and incident.exposure_end is None:
        incident.exposure_end = end_time
        db.commit()


def reset_incident_for_refresh(db: Session, incident_id: str) -> IncidentRecord | None:
    """
    Clear derived forensic output before a manual CloudTrail refresh.

    CloudTrail can deliver events several minutes late, so a manual rerun should
    replace stale event/report data instead of appending duplicate events.
    """
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        return None

    db.query(ORMForensicEvent).filter(
        ORMForensicEvent.incident_id == incident_id
    ).delete(synchronize_session=False)

    incident.status = "collecting"
    incident.overall_severity = None
    incident.report_text = None
    incident.remediation_steps = []
    incident.gdpr_flag = False
    incident.financial_impact = None
    db.commit()
    db.refresh(incident)
    return incident


# ---------------------------------------------------------------------------
# ForensicEvent helpers
# ---------------------------------------------------------------------------

def save_forensic_events(
    db: Session,
    incident_id: str,
    events: list[PydanticForensicEvent],
) -> list[ORMForensicEvent]:
    """
    Persist a list of Pydantic ForensicEvent objects into the forensic_events table.
    Returns the created ORM rows.
    """
    orm_events: list[ORMForensicEvent] = []
    for event in events:
        error_code = event.error_code
        is_denied = (
            error_code is not None
            and "AccessDenied" in error_code
        )
        # Extract principal ARN from raw CloudTrail data when available.
        principal_arn = None
        raw = event.raw_data or {}
        user_identity = raw.get("userIdentity") or {}
        principal_arn = user_identity.get("arn")

        orm_event = ORMForensicEvent(
            event_id=event.event_id,
            incident_id=incident_id,
            platform=event.platform,
            timestamp=event.timestamp,
            api_action=event.api_action,
            event_source=event.event_source,
            source_ip=event.source_ip,
            user_agent=event.user_agent,
            affected_resource=event.affected_resource,
            resource_type=event.resource_type,
            success=event.success,
            error_code=error_code,
            is_denied=is_denied,
            principal_arn=principal_arn,
            # GCP / Azure identity fields (None for AWS events)
            principal_id=getattr(event, "principal_id", None),
            location=getattr(event, "location", None),
            raw_data=event.raw_data,
            impact_category=event.impact_category,
            severity_weight=event.severity_weight,
        )
        db.add(orm_event)
        orm_events.append(orm_event)

    db.commit()
    for orm_event in orm_events:
        db.refresh(orm_event)
    return orm_events


# ---------------------------------------------------------------------------
# CollectionStatus helpers
# ---------------------------------------------------------------------------

def save_collection_status(
    db: Session,
    *,
    incident_id: str,
    platform: str = "aws",
    status: str,
    event_count: int = 0,
    error_message: str | None = None,
) -> CollectionStatus:
    """Record the outcome of a forensic collection attempt."""
    record = CollectionStatus(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        platform=platform,
        status=status,
        event_count=event_count,
        error_message=error_message,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def finalize_non_forensic_incident(
    db: Session,
    incident_id: str,
    unavailable_reason: str | None = None,
) -> IncidentRecord | None:
    """
    Complete a Tier-2 incident without running a collector.

    Tier-2 platforms expose no queryable per-credential audit log, so running a
    collector would return nothing and leave the incident stuck in 'collecting'
    forever — a state the dashboard renders identically to a real in-flight
    investigation. Worse, an empty timeline reads as "nothing happened", which
    is precisely the false reassurance BreachTrace exists to eliminate.

    So the incident is marked complete immediately, carrying the reason
    reconstruction is impossible and generic remediation. Severity stays NULL
    rather than defaulting to Low: we genuinely do not know the blast radius,
    and claiming it was low would be a fabrication.
    """
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        return None

    incident.status = "complete"
    if unavailable_reason:
        incident.unavailable_reason = unavailable_reason
    incident.report_text = _non_forensic_report(incident, unavailable_reason)
    incident.report_source = "deterministic"
    incident.remediation_steps = _non_forensic_remediation(incident)
    db.commit()
    db.refresh(incident)
    return incident


def _non_forensic_report(incident: IncidentRecord, reason: str | None) -> str:
    """Deterministic report for Tier-2 incidents — no LLM call needed."""
    return (
        f"## Credential candidate detected\n\n"
        f"A candidate matching **{incident.credential_type.replace('_', ' ')}** "
        f"(`{incident.credential_hint}`) was detected in source associated with {incident.repo_url}. "
        f"Syntax matching does not prove the credential is valid or active.\n\n"
        f"## Why there is no activity timeline\n\n"
        f"{reason or 'BreachTrace does not collect activity for this credential type.'}\n\n"
        f"**This is not evidence that the credential went unused.** It means the "
        f"activity is not reconstructed by BreachTrace. Treat the credential as compromised "
        f"and rotate it immediately.\n"
    )


def _non_forensic_remediation(incident: IncidentRecord) -> list[str]:
    """Generic but specific-enough remediation for a Tier-2 leak."""
    return [
        f"☐ Revoke the exposed {incident.credential_type.replace('_', ' ')} "
        f"({incident.credential_hint}) in the provider's console now",
        "☐ Issue a replacement credential and update every deployment that used it",
        f"☐ Purge the secret from git history in {incident.repo_url} "
        "(rotation alone leaves it readable in past commits)",
        "☐ Review any provider-side billing or usage dashboards for unexpected activity "
        "during the exposure window",
        "☐ Enable secret scanning on the repository to catch the next one before push",
    ]
