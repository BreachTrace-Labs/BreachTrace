"""
GET /incidents
GET /incidents/{incident_id}
-----------------------------
Returns stored incidents and their forensic events.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.crud import get_incident, list_incidents
from db.database import get_db

router = APIRouter(prefix="/incidents", tags=["incidents"])


# ---------------------------------------------------------------------------
# Response schemas (flat — avoids circular ORM relationships in JSON)
# ---------------------------------------------------------------------------

class ForensicEventOut(BaseModel):
    event_id: str
    platform: str
    timestamp: datetime
    api_action: str
    event_source: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    affected_resource: Optional[str]
    resource_type: Optional[str]
    success: bool
    error_code: Optional[str]
    is_denied: bool
    impact_category: Optional[str]
    severity_weight: Optional[int]

    class Config:
        from_attributes = True


class IncidentSummaryOut(BaseModel):
    incident_id: str
    credential_type: str
    credential_hint: str
    repo_url: str
    commit_hash: Optional[str]
    exposure_start: datetime
    exposure_end: Optional[datetime]
    status: str
    overall_severity: Optional[int]
    gdpr_flag: bool
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentDetailOut(IncidentSummaryOut):
    events: list[ForensicEventOut] = []
    report_text: Optional[str]
    remediation_steps: list[str]
    financial_impact: Optional[str]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=list[IncidentSummaryOut])
def list_all_incidents(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """Return the most recent incidents, newest first."""
    return list_incidents(db, limit=limit, offset=offset)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Return a single incident with all its forensic events."""
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
