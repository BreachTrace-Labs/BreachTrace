"""
GET /incidents
GET /incidents/stats
GET /incidents/{incident_id}
GET /incidents/{incident_id}/timeline
POST /incidents/{incident_id}/refresh
PATCH /incidents/{incident_id}
------------------------------
Returns stored incidents and their forensic events.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from db.crud import get_incident, list_incidents, reset_incident_for_refresh
from db.database import get_db
from db.models import CREDENTIAL_TYPE_TO_PLATFORM, ExperimentRun
from pipeline import run_collection_pipeline
from scorer.severity import (
    build_compliance_reasons,
    check_gdpr_flag,
    check_pcidss_flag,
    check_soc2_flag,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
legacy_router = APIRouter(prefix="/incident", tags=["incidents"])

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
    # GCP / Azure identity and location
    principal_id: Optional[str] = None
    location: Optional[str] = None
    raw_data: dict = Field(default_factory=dict)

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
    # Multi-platform fields
    platform: str = "aws"
    principal_id: Optional[str] = None
    gcp_project_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    # Forensic tier: 1 = blast radius reconstructable, 2 = detection only.
    # The UI branches on this to decide between a timeline and the
    # "forensics unavailable" panel, so it must appear on the LIST response
    # too — not just the detail one — or the dashboard cannot label rows.
    forensic_tier: int = 1
    unavailable_reason: Optional[str] = None

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
    report_text: Optional[str] = None
    remediation_steps: list[str] = []
    estimated_financial_impact: Optional[str] = Field(None, validation_alias="financial_impact")
    # Computed fields — not stored in DB, derived from events at request time.
    pcidss_flag: bool = False
    soc2_flag: bool = False
    compliance_reasons: list[str] = []

    class Config:
        from_attributes = True
        populate_by_name = True


class RefreshResponse(BaseModel):
    incident_id: str
    status: str
    message: str


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
    """Return a single incident with all its forensic events and compliance flags."""
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    out = IncidentDetailOut.model_validate(incident)

    # Compute per-regulation compliance flags from live event data.
    gdpr = check_gdpr_flag(incident.events)
    pcidss = check_pcidss_flag(incident.events)
    soc2 = check_soc2_flag(incident.events)
    out.pcidss_flag = pcidss
    out.soc2_flag = soc2
    # Refresh gdpr_flag in case the DB value pre-dates the improved detector.
    out.gdpr_flag = incident.gdpr_flag or gdpr
    out.compliance_reasons = build_compliance_reasons(
        gdpr=out.gdpr_flag,
        pcidss=pcidss,
        soc2=soc2,
        events=incident.events,
    )
    return out


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
# Manual CloudTrail refresh endpoint
# ---------------------------------------------------------------------------

def _derive_platform(incident) -> str:
    """
    Platform for an incident.

    Delegates to IncidentRecord.platform, which uses the explicit
    CREDENTIAL_TYPE_TO_PLATFORM map. The previous substring form
    (`"gcp" in credential_type`) silently mis-routed the SaaS credential types
    and could not express that a Firebase key collects through GCP.
    """
    return CREDENTIAL_TYPE_TO_PLATFORM.get(
        (getattr(incident, "credential_type", "") or "").lower(), "aws"
    )


def _queue_incident_refresh(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: Session,
) -> RefreshResponse:
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    platform = _derive_platform(incident)

    # Pick the right credential for collection:
    # AWS uses access_key_id; GCP/Azure use principal_id (email / client ID)
    if platform == "aws":
        credential = incident.access_key_id
        if not credential:
            raise HTTPException(
                status_code=422,
                detail="Incident does not have an AWS access key ID to query CloudTrail.",
            )
    else:
        credential = incident.principal_id
        if not credential:
            raise HTTPException(
                status_code=422,
                detail=f"Incident does not have a principal ID to query {platform.upper()} logs.",
            )

    platform_msg = {
        "aws": "CloudTrail can take up to 15 minutes to surface fresh events.",
        "gcp": "GCP Cloud Audit Logs query started.",
        "azure": "Azure Activity Log query started.",
    }.get(platform, "Log query started.")

    reset_incident_for_refresh(db, incident_id)
    background_tasks.add_task(
        run_collection_pipeline,
        incident.incident_id,
        credential,
        incident.exposure_start,
        platform=platform,
        refresh_existing=True,
    )

    return RefreshResponse(
        incident_id=incident.incident_id,
        status="collecting",
        message=f"Forensics refresh started. {platform_msg}",
    )


@router.post("/{incident_id}/refresh", response_model=RefreshResponse, status_code=202)
def refresh_incident_forensics(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Manually re-run forensic collection for an incident.

    This is useful after GitHub webhook detection when AWS CloudTrail events are
    still delayed. Existing derived events/report output are cleared and the
    normal collector → classifier → scorer → reporter pipeline is queued again.
    """
    return _queue_incident_refresh(incident_id, background_tasks, db)


@legacy_router.post("/{incident_id}/refresh", response_model=RefreshResponse, status_code=202)
def refresh_incident_forensics_legacy_path(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Compatibility alias for the singular /incident/{id}/refresh path."""
    return _queue_incident_refresh(incident_id, background_tasks, db)


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
