"""
GET /incidents
GET /incidents/stats
GET /incidents/{incident_id}
GET /incidents/{incident_id}/timeline
PATCH /incidents/{incident_id}
------------------------------
Returns stored incidents and their forensic events.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from db.crud import get_incident, list_incidents
from db.database import get_db
from db.models import ExperimentRun

router = APIRouter(prefix="/incidents", tags=["incidents"])

_SEVERITY_LABELS: dict[int, str] = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

# Reverse mapping: string labels → DB integer (case-insensitive on lookup)
_SEVERITY_STR_TO_INT: dict[str, int] = {
    "low": 1, "medium": 2, "high": 3, "critical": 4,
    "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
    "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
}


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
    access_key_id: Optional[str]
    repo_url: str
    commit_hash: Optional[str]
    exposure_start: datetime
    exposure_end: Optional[datetime]
    status: str
    overall_severity: Optional[str]
    gdpr_flag: bool
    created_at: datetime

    @field_validator("overall_severity", mode="before")
    @classmethod
    def coerce_severity(cls, v: object) -> Optional[str]:
        if isinstance(v, int):
            return _SEVERITY_LABELS.get(v)
        return v  # type: ignore[return-value]

    class Config:
        from_attributes = True


class IncidentDetailOut(IncidentSummaryOut):
    events: list[ForensicEventOut] = []
    report_text: Optional[str]
    remediation_steps: list[str]
    estimated_financial_impact: Optional[str] = Field(None, validation_alias="financial_impact")

    class Config:
        from_attributes = True
        populate_by_name = True


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


@router.get("/stats")
def get_incident_stats(db: Session = Depends(get_db)):
    """Aggregate statistics over all experiment runs for the Research page."""
    try:
        runs = db.query(ExperimentRun).all()
    except Exception:
        runs = []
    total = len(runs)
    detection_times = [r.detection_time_s for r in runs if r.detection_time_s is not None]
    report_times = [r.report_time_s for r in runs if r.report_time_s is not None]
    sev_dist: Counter[str] = Counter()
    for r in runs:
        if r.overall_severity:
            sev_dist[str(r.overall_severity).upper()] += 1
    return {
        "total_runs": total,
        "avg_detection_time_s": sum(detection_times) / len(detection_times) if detection_times else None,
        "avg_report_time_s": sum(report_times) / len(report_times) if report_times else None,
        "severity_distribution": dict(sev_dist),
        "detection_target_s": 30,
        "report_target_s": 60,
    }


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


# ---------------------------------------------------------------------------
# Timeline endpoint
# ---------------------------------------------------------------------------

@router.get("/{incident_id}/timeline", response_model=list[ForensicEventOut])
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """
    Return forensic events for an incident sorted by timestamp.

    Events include ``impact_category`` and ``severity_weight`` once the
    pipeline has reached the *classifying* stage or beyond.
    """
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    # The relationship has ``order_by=ForensicEvent.timestamp`` so the list is
    # already chronologically sorted.
    return incident.events


# ---------------------------------------------------------------------------
# PATCH endpoint
# ---------------------------------------------------------------------------

class IncidentPatch(BaseModel):
    """Subset of IncidentRecord fields that can be updated after creation."""

    report_text: Optional[str] = None
    remediation_steps: Optional[list[str]] = None
    gdpr_flag: Optional[bool] = None
    financial_impact: Optional[str] = None
    # Accept "Low" / "Medium" / "High" / "Critical" (any casing)
    overall_severity: Optional[str] = None


@router.patch("/{incident_id}", response_model=IncidentDetailOut)
def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    db: Session = Depends(get_db),
):
    """
    Partially update an incident record.

    Used by the pipeline (via direct DB access) and by tests / manual
    intervention.  Only supplied fields are changed; omitted fields are left
    as-is.
    """
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if body.report_text is not None:
        incident.report_text = body.report_text

    if body.remediation_steps is not None:
        incident.remediation_steps = body.remediation_steps

    if body.gdpr_flag is not None:
        incident.gdpr_flag = body.gdpr_flag

    if body.financial_impact is not None:
        incident.financial_impact = body.financial_impact

    if body.overall_severity is not None:
        severity_int = _SEVERITY_STR_TO_INT.get(body.overall_severity)
        if severity_int is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid overall_severity '{body.overall_severity}'. "
                    "Must be one of: Low, Medium, High, Critical."
                ),
            )
        incident.overall_severity = severity_int

    db.commit()
    db.refresh(incident)
    return incident
