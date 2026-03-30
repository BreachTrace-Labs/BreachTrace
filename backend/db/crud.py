"""CRUD helpers — thin wrappers over SQLAlchemy ORM used by route handlers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.orm import Session

from db.models import IncidentRecord


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
