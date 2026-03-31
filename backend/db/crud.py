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
    access_key_id: str,
    repo_url: str,
    commit_hash: str,
    exposure_start: datetime,
) -> IncidentRecord:
    """Insert a new incident row and return the persisted object."""
    incident = IncidentRecord(
        incident_id=str(uuid.uuid4()),
        credential_type=credential_type,
        credential_hint=credential_hint,
        access_key_id=access_key_id,
        repo_url=repo_url,
        commit_hash=commit_hash,
        exposure_start=exposure_start,
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
