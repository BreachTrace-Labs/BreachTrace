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
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from access import accessible_project_ids, assert_project_access, incident_access
from auth import get_active_user, require_admin_or_lead, require_single_organisation
from audit import public as audit_public, record
from db.crud import get_incident, list_incidents, reset_incident_for_refresh
from db.database import get_db
from db.models import AuditLog, CREDENTIAL_TYPE_TO_PLATFORM, ExperimentRun, IncidentRecord, ProjectMember, User
from pipeline import run_collection_pipeline
from scorer.severity import (
    build_compliance_reasons,
    check_gdpr_flag,
    check_pcidss_flag,
    check_soc2_flag,
    compute_financial_impact_lines,
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
    project_id: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_to_name: Optional[str] = None
    dismissed: bool = False
    dismissed_by: Optional[str] = None
    dismissed_by_name: Optional[str] = None
    dismissed_at: Optional[datetime] = None
    dismissal_reason: Optional[str] = None
    dismissal_type: Optional[str] = None
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


class FinancialImpactLineOut(BaseModel):
    """One costed finding. Mirrors scorer.severity.FinancialImpactLine."""

    platform: str
    kind: str
    label: str
    text: str
    amount: Optional[float] = None
    currency: Optional[str] = None
    unit: Optional[str] = None
    quantity: Optional[int] = None
    # True only where money demonstrably moved (Stripe). Everything else is a
    # list-price estimate, and the UI must be able to tell them apart.
    actual: bool = False


class IncidentDetailOut(IncidentSummaryOut):
    events: list[ForensicEventOut] = []
    report_text: Optional[str] = None
    # deterministic | local_model | gemini — who wrote the report prose.
    report_source: Optional[str] = None
    remediation_steps: list[str] = []
    estimated_financial_impact: Optional[str] = Field(None, validation_alias="financial_impact")
    # Computed fields — not stored in DB, derived from events at request time.
    pcidss_flag: bool = False
    soc2_flag: bool = False
    compliance_reasons: list[str] = []
    # Structured view of estimated_financial_impact. Computed per request from
    # the same events, following the precedent of the compliance flags above —
    # so no migration is needed and existing incidents get it immediately.
    financial_impact_lines: list[FinancialImpactLineOut] = []

    class Config:
        from_attributes = True
        populate_by_name = True


class RefreshResponse(BaseModel):
    incident_id: str
    status: str
    message: str


class DismissRequest(BaseModel):
    dismissal_type: Literal['false_positive', 'test_credential', 'acknowledged', 'rotated']
    reason: str = Field(min_length=10, max_length=500)

    @field_validator('reason')
    @classmethod
    def nonempty_reason(cls, value):
        value = value.strip()
        if len(value) < 10:
            raise ValueError('Reason must contain at least 10 non-whitespace characters')
        return value


class AssignRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)


def add_user_names(output: IncidentSummaryOut, incident: IncidentRecord, db: Session):
    ids = [value for value in (incident.assigned_to, incident.dismissed_by) if value]
    names = dict(db.query(User.id, User.full_name).filter(User.id.in_(ids)).all()) if ids else {}
    output.assigned_to_name = names.get(incident.assigned_to)
    output.dismissed_by_name = names.get(incident.dismissed_by)
    return output


def audit_incident_view(request: Request, incident: IncidentRecord = Depends(incident_access),
                        user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    record(db, user, 'incident.viewed', request, project_id=incident.project_id, incident_id=incident.incident_id)
    db.commit()



# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=list[IncidentSummaryOut])
def list_all_incidents(
    limit: int = 50,
    offset: int = 0,
    project_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_active_user),
):
    """Return the most recent incidents, newest first."""
    if project_id:
        assert_project_access(project_id, user, db)
    query = db.query(IncidentRecord).filter(IncidentRecord.project_id.in_(accessible_project_ids(user, db)))
    if project_id:
        query = query.filter(IncidentRecord.project_id == project_id)
    incidents = query.order_by(IncidentRecord.exposure_start.desc()).offset(max(0, offset)).limit(min(max(1, limit), 500)).all()
    ids = {value for incident in incidents for value in (incident.assigned_to, incident.dismissed_by) if value}
    names = dict(db.query(User.id, User.full_name).filter(User.id.in_(ids)).all()) if ids else {}
    result = []
    for incident in incidents:
        item = IncidentSummaryOut.model_validate(incident)
        item.assigned_to_name = names.get(incident.assigned_to)
        item.dismissed_by_name = names.get(incident.dismissed_by)
        result.append(item)
    return result


@router.get("/stats", dependencies=[Depends(require_admin_or_lead), Depends(require_single_organisation)])
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


@router.get("/{incident_id}", response_model=IncidentDetailOut, dependencies=[Depends(audit_incident_view)])
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
    out.financial_impact_lines = [
        FinancialImpactLineOut(**asdict(line))
        for line in compute_financial_impact_lines(incident.events)
    ]
    return add_user_names(out, incident, db)


@router.get("/{incident_id}/report.pdf", dependencies=[Depends(incident_access)])
def download_incident_pdf(incident_id: str, db: Session = Depends(get_db)):
    """Per-incident PDF: key details, forensic analysis, remediation, timeline."""
    from fastapi.responses import Response

    from reporter.pdf import build_incident_pdf

    detail = get_incident_detail(incident_id, db)
    pdf = build_incident_pdf(detail)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="breachtrace-{incident_id[:8]}.pdf"'},
    )


# ---------------------------------------------------------------------------
# Timeline endpoint
# ---------------------------------------------------------------------------

@router.get("/{incident_id}/timeline", response_model=list[ForensicEventOut], dependencies=[Depends(incident_access)])
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


@router.post('/{incident_id}/dismiss', response_model=IncidentDetailOut)
def dismiss_incident(incident_id: str, body: DismissRequest, request: Request,
                     incident: IncidentRecord = Depends(incident_access),
                     user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    incident.dismissed = True
    incident.dismissal_type = body.dismissal_type
    incident.dismissal_reason = body.reason
    incident.dismissed_by = user.id
    incident.dismissed_at = datetime.now(timezone.utc)
    record(db, user, 'incident.dismissed', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'dismissal_type': body.dismissal_type})
    db.commit()
    return get_incident_detail(incident_id, db)


@router.post('/{incident_id}/assign', response_model=IncidentDetailOut, dependencies=[Depends(require_admin_or_lead)])
def assign_incident(incident_id: str, body: AssignRequest, request: Request, background_tasks: BackgroundTasks,
                    incident: IncidentRecord = Depends(incident_access),
                    user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    target = (db.query(User).join(ProjectMember, ProjectMember.user_id == User.id)
              .filter(User.id == body.user_id, User.organisation_id == user.organisation_id,
                      User.is_active.is_(True), ProjectMember.project_id == incident.project_id).first())
    if target is None:
        raise HTTPException(400, 'Assignee must be an active member of this project')
    incident.assigned_to = target.id
    record(db, user, 'incident.assigned', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'assigned_to': target.id})
    db.commit()
    from notifications import notify_incident_assigned_by_id
    background_tasks.add_task(notify_incident_assigned_by_id, incident.incident_id, target.id)
    return get_incident_detail(incident_id, db)


@router.get('/{incident_id}/audit', dependencies=[Depends(require_admin_or_lead)])
def incident_audit(incident_id: str, incident: IncidentRecord = Depends(incident_access),
                   user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    rows = (db.query(AuditLog, User.full_name).outerjoin(User, User.id == AuditLog.actor_user_id)
            .filter(AuditLog.organisation_id == user.organisation_id, AuditLog.incident_id == incident.incident_id)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(200).all())
    return [audit_public(entry, name) for entry, name in rows]



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
    user: User | None = None,
    request: Request | None = None,
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
        # The leaked Stripe key is never stored, so a refresh reads the account
        # through the configured key.
        "stripe": "Stripe Events query started using STRIPE_API_KEY.",
        "twilio": "Twilio Messages and Calls query started.",
    }.get(platform, "Log query started.")

    if user is not None and request is not None:
        record(db, user, 'incident.refreshed', request, project_id=incident.project_id, incident_id=incident.incident_id)
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


@router.post("/{incident_id}/refresh", response_model=RefreshResponse, status_code=202, dependencies=[Depends(require_admin_or_lead), Depends(incident_access)])
def refresh_incident_forensics(
    incident_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_or_lead),
):
    """
    Manually re-run forensic collection for an incident.

    This is useful after GitHub webhook detection when AWS CloudTrail events are
    still delayed. Existing derived events/report output are cleared and the
    normal collector → classifier → scorer → reporter pipeline is queued again.
    """
    return _queue_incident_refresh(incident_id, background_tasks, db, user, request)


@legacy_router.post("/{incident_id}/refresh", response_model=RefreshResponse, status_code=202, dependencies=[Depends(require_admin_or_lead), Depends(incident_access)])
def refresh_incident_forensics_legacy_path(
    incident_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_or_lead),
):
    """Compatibility alias for the singular /incident/{id}/refresh path."""
    return _queue_incident_refresh(incident_id, background_tasks, db, user, request)


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


@router.patch("/{incident_id}", response_model=IncidentDetailOut, dependencies=[Depends(require_admin_or_lead), Depends(incident_access)])
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
        incident.report_source = None  # edited by hand; no longer any writer's output

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
