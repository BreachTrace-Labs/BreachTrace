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
from datetime import datetime, timedelta, timezone
import hmac
import os
import re
import uuid
from urllib.parse import urlsplit
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from access import accessible_project_ids, assert_project_access, incident_access
from auth import get_active_user, require_admin_or_lead, require_single_organisation, require_single_organisation_database
from audit import public as audit_public, record
from db.crud import get_incident, list_incidents
from db.database import get_db
from db.models import AuditLog, AzureSecretOccurrence, ExposureObservation, GCPKeyAssociation, CREDENTIAL_TYPE_TO_PLATFORM, ExperimentRun, IncidentRecord, ProjectMember, User, ForensicEvent as StoredEvent
from normalizer.time_window import after_exposure, within_exposure
from routers.settings import local_operator
from pipeline import run_collection_pipeline
from redaction import mask_identifier, redact
from scorer.blast_radius import dynamic_blast_radius
from scorer.compliance import compliance_review_flags
from scorer.severity import (
    build_compliance_reasons,
    check_gdpr_flag,
    check_pcidss_flag,
    check_soc2_flag,
    compute_financial_impact_lines,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
legacy_router = APIRouter(prefix="/incident", tags=["incidents"])
stream_router = APIRouter(prefix="/incidents", tags=["stripe request stream"])

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
    gcp_key_attribution: Optional[Literal['matched', 'different_key', 'unavailable']] = None

    @field_validator("api_action", "event_source", "source_ip", "user_agent", "affected_resource", "resource_type", "error_code", "principal_id", "location", mode="before")
    @classmethod
    def redact_text(cls, value):
        return redact(value)

    @field_validator("raw_data", mode="before")
    @classmethod
    def redact_raw_data(cls, value):
        return redact(value or {})

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
    azure_repeat_count: int = 0

    @field_validator("access_key_id", mode="before")
    @classmethod
    def mask_access_key_id(cls, value):
        return mask_identifier(value)

    @field_validator("principal_id", mode="before")
    @classmethod
    def redact_principal(cls, value):
        return redact(value)

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
    # Twilio provider-reported charges are account activity, not proof that a
    # particular exposed key was responsible.
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
    compliance_review_flags: list[dict[str, str]] = []
    # Structured view of estimated_financial_impact. Computed per request from
    # the same events, following the precedent of the compliance flags above —
    # so no migration is needed and existing incidents get it immediately.
    financial_impact_lines: list[FinancialImpactLineOut] = []
    financial_history_lines: list[FinancialImpactLineOut] = []
    collection_status: Optional[str] = None
    collection_error: Optional[str] = None
    dynamic_blast_radius: dict | None = None
    azure_secret_occurrences: list[dict] = []
    gcp_key_association: dict | None = None
    gcp_record_correlation: dict | None = None
    gcp_classification_coverage: dict | None = None

    @field_validator("report_text", "remediation_steps", mode="before")
    @classmethod
    def redact_report(cls, value):
        return redact(value)

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


class ExposureObservationIn(BaseModel):
    kind: Literal['revoked', 'rotated', 'expired', 'active', 'inconclusive']
    observed_at: datetime
    source: str = Field(min_length=3, max_length=200)
    confidence: Literal['low', 'medium', 'high']

    @field_validator('source')
    @classmethod
    def validate_source(cls, value):
        value = value.strip()
        if len(value) < 3:
            raise ValueError('Describe the evidence source')
        return redact(value)

    @field_validator('observed_at')
    @classmethod
    def validate_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('Observation time must include a timezone')
        if value > datetime.now(timezone.utc):
            raise ValueError('Observation time cannot be in the future')
        return value


def observation_data(row, actor):
    return {'id': row.id, 'kind': row.kind, 'observed_at': row.observed_at,
            'recorded_at': row.recorded_at, 'recorded_by': actor, 'source': redact(row.source),
            'confidence': row.confidence, 'credential_hint': row.credential_hint,
            'verification': 'operator_reported'}


@router.get('/{incident_id}/exposure-observations')
def list_exposure_observations(incident: IncidentRecord = Depends(incident_access), db: Session = Depends(get_db)):
    rows = (db.query(ExposureObservation, User.full_name).join(User, User.id == ExposureObservation.recorded_by)
            .filter(ExposureObservation.incident_id == incident.incident_id)
            .order_by(ExposureObservation.recorded_at.desc(), ExposureObservation.id.desc()).all())
    return [observation_data(row, actor) for row, actor in rows]


@router.post('/{incident_id}/exposure-observations', status_code=201)
def create_exposure_observation(body: ExposureObservationIn, request: Request,
                                incident: IncidentRecord = Depends(incident_access),
                                user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    row = ExposureObservation(incident_id=incident.incident_id, recorded_by=user.id, kind=body.kind,
                              observed_at=body.observed_at, source=body.source,
                              confidence=body.confidence, credential_hint=incident.credential_hint)
    db.add(row)
    db.flush()
    record(db, user, 'incident.exposure_observation_recorded', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'observation_id': row.id, 'kind': row.kind})
    db.commit()
    db.refresh(row)
    return observation_data(row, user.full_name)


class GCPKeyAssociationIn(BaseModel):
    key_id: str = Field(pattern=r'^[a-fA-F0-9]{40}$')
    confirms_incident_key: Literal[True]


@router.post('/{incident_id}/gcp-key-association', status_code=200)
def associate_gcp_key(body: GCPKeyAssociationIn, request: Request,
                      incident: IncidentRecord = Depends(incident_access),
                      user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    from gcp_attribution import key_digest
    if incident.platform not in ('gcp', 'firebase') or not incident.principal_id:
        raise HTTPException(422, 'A GCP service-account incident with an identified account is required')
    row = db.get(GCPKeyAssociation, incident.incident_id)
    if row is None:
        row = GCPKeyAssociation(incident_id=incident.incident_id)
        db.add(row)
    row.key_digest = key_digest(body.key_id)
    row.key_hint = body.key_id[:4] + '…' + body.key_id[-4:]
    row.recorded_by = user.id
    row.source = 'operator_reported'
    row.recorded_at = datetime.now(timezone.utc)
    record(db, user, 'incident.gcp_key_associated', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'key_hint': row.key_hint})
    db.commit()
    return {'key_hint': row.key_hint, 'recorded_by': user.full_name, 'recorded_at': row.recorded_at,
            'verification': 'operator_reported'}


class AzureSignInsRequest(BaseModel):
    credential_key_id: uuid.UUID | None = None


@router.post('/{incident_id}/azure-signins')
def azure_signins(body: AzureSignInsRequest, request: Request,
                  incident: IncidentRecord = Depends(incident_access),
                  user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    from collection_credentials import ReaderConfigurationError, project_reader
    from collectors.azure_signins import SignInCollectionError, collect_signins
    if incident.platform != 'azure' or not incident.principal_id:
        raise HTTPException(422, 'Associate an Azure application with this incident first.')
    try:
        uuid.UUID(incident.principal_id)
        reader = project_reader(db, incident, 'azure')
    except ValueError as exc:
        raise HTTPException(422, str(exc) if isinstance(exc, ReaderConfigurationError) else 'The incident application ID is invalid.') from None
    if reader is None:
        raise HTTPException(422, 'Configure a verified Azure reader for this project.')
    record(db, user, 'incident.azure_signins_requested', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'key_comparison': body.credential_key_id is not None})
    db.commit()
    try:
        return collect_signins(reader, incident.principal_id, str(body.credential_key_id) if body.credential_key_id else None)
    except SignInCollectionError as exc:
        raise HTTPException(502, str(exc)) from None


class TwilioAccountRequest(BaseModel):
    account_sid: str = Field(pattern=r"^AC[0-9a-fA-F]{32}$")


class AzureApplicationRequest(BaseModel):
    client_id: uuid.UUID


class StripeRequestLogIn(BaseModel):
    created_at: int = Field(gt=0)
    livemode: bool
    method: str = Field(pattern=r"^(GET|POST|DELETE|PUT|PATCH)$")
    request_id: str = Field(pattern=r"^req_[A-Za-z0-9]+$", max_length=100)
    status: int = Field(ge=100, le=599)
    url: str = Field(min_length=1, max_length=2048)
    account_confirmed: bool


def _safe_stripe_path(value) -> str | None:
    if not isinstance(value, str) or len(value) > 4096:
        return None
    path = urlsplit(value).path
    if not re.fullmatch(r"/v[0-9]+(?:/[A-Za-z0-9_.-]+)*", path) or len(path) > 512:
        return None
    id_segment = re.compile(r"^(?:acct|cus|pi|ch|in|evt|req|pm|price|prod|sub|seti|cs|tok|src|ba|card|file|payout|re|txn|fee|refund|tr|po)_[A-Za-z0-9]+$")
    return "/" + "/".join("…" if id_segment.fullmatch(s) else s for s in path.strip("/").split("/"))


def stripe_request_log_auth(request: Request) -> None:
    """Allow loopback local development or a shared secret from the stream sidecar."""
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if request.client and request.client.host in local_hosts and request.url.hostname in local_hosts:
        return
    expected = os.getenv("STRIPE_LOG_INGEST_TOKEN", "")
    supplied = request.headers.get("authorization", "")
    if not expected or not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:], expected):
        raise HTTPException(403, "Stripe request-log stream is not authorized")


def _store_stripe_request_log(db: Session, incident, item: dict) -> str:
    source = "stripe-cli-request-log"
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"breachtrace:{source}:{incident.incident_id}:{item['request_id']}"))
    if db.get(StoredEvent, event_id):
        return "duplicate"
    method, path, status = item["method"], item["path"], item["status"]
    is_read = method == "GET"
    db.add(StoredEvent(
        event_id=event_id, incident_id=incident.incident_id, platform="stripe", timestamp=item["timestamp"],
        api_action=f"{method} {path}"[:100], event_source="stripe-cli-request-log",
        affected_resource=path, resource_type="stripe_request", principal_id=item["request_id"],
        success=200 <= status < 300, error_code=str(status) if status >= 400 else None,
        impact_category="data_access" if is_read else "resource_abuse", severity_weight=2,
        raw_data={"source": source, "request_id": item["request_id"], "http_status": status,
                  "method": method, "path": path, "livemode": item["livemode"],
                  "attribution": "sandbox account activity; key identity not provided"},
    ))
    return "added"


@stream_router.post("/{incident_id}/stripe-request-logs", dependencies=[Depends(stripe_request_log_auth), Depends(require_single_organisation_database)])
def add_stripe_request_log(incident_id: str, body: StripeRequestLogIn, db: Session = Depends(get_db)):
    """Accept an explicitly associated sandbox CLI record, retaining metadata only."""
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    if incident.credential_type != "stripe_secret_key" or not (incident.credential_hint or "").startswith(("sk_test_", "rk_test_")):
        raise HTTPException(400, "Request-log streaming is available for Stripe test-mode incidents only")
    if body.livemode or not body.account_confirmed:
        raise HTTPException(400, "Confirm the CLI is connected to this incident's sandbox")
    try:
        timestamp = datetime.fromtimestamp(body.created_at, timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise HTTPException(400, "Invalid request timestamp")
    exposure = incident.exposure_start
    if exposure.tzinfo is None:
        exposure = exposure.replace(tzinfo=timezone.utc)
    if timestamp < exposure - timedelta(minutes=120) or timestamp > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise HTTPException(400, "Request is outside this incident's collection window")
    if incident.exposure_end and timestamp > incident.exposure_end.replace(tzinfo=incident.exposure_end.tzinfo or timezone.utc):
        raise HTTPException(400, "Request is after the incident's exposure ended")
    # Do not store query strings, bodies, error messages, or credential material.
    path = _safe_stripe_path(body.url)
    if not path:
        raise HTTPException(400, "Invalid Stripe request path")
    item = {"request_id": body.request_id, "timestamp": timestamp, "method": body.method,
            "status": body.status, "path": path, "livemode": False}
    result = _store_stripe_request_log(db, incident, item)
    db.commit()
    return {"status": result}


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
    counts = dict(db.query(AzureSecretOccurrence.incident_id, func.count(AzureSecretOccurrence.id))
                  .filter(AzureSecretOccurrence.incident_id.in_([row.incident_id for row in incidents]))
                  .group_by(AzureSecretOccurrence.incident_id).all()) if incidents else {}
    result = []
    for incident in incidents:
        item = IncidentSummaryOut.model_validate(incident)
        item.azure_repeat_count = max(0, counts.get(incident.incident_id, 0) - 1)
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
    if incident.platform == 'gcp':
        # Legacy persisted estimates inferred prices and sizes from action names.
        out.estimated_financial_impact = None
        from gcp_correlation import correlate_gcp_records
        out.gcp_record_correlation = redact(correlate_gcp_records(incident.events))
        records = [event for event in incident.events if event.platform == 'gcp']
        unknown = sum(not event.impact_category for event in records)
        out.gcp_classification_coverage = {'record_count': len(records), 'classified_count': len(records) - unknown,
                                           'unclassified_count': unknown}
    # Older GCP rows predate recognition of canonical PERMISSION_DENIED.
    for event in out.events:
        if event.platform == 'gcp' and event.error_code == '7':
            event.is_denied = True
    occurrences = db.query(AzureSecretOccurrence).filter_by(incident_id=incident.incident_id).order_by(AzureSecretOccurrence.observed_at).all()
    out.azure_secret_occurrences = [{'commit_hash': item.commit_hash, 'observed_at': item.observed_at} for item in occurrences]
    out.azure_repeat_count = max(0, len(occurrences) - 1)
    association = db.get(GCPKeyAssociation, incident.incident_id)
    if association is not None:
        from gcp_attribution import event_attribution
        actor = db.get(User, association.recorded_by) if association.recorded_by else None
        out.gcp_key_association = {'key_hint': association.key_hint, 'recorded_by': actor.full_name if actor else None,
                                   'recorded_at': association.recorded_at, 'verification': association.source}
        for source, event in zip(incident.events, out.events):
            event.gcp_key_attribution = event_attribution(source, incident, association)
    if incident.collection_statuses and incident.status not in ("collecting", "classifying", "scoring", "reporting"):
        latest = max(incident.collection_statuses, key=lambda status: status.queried_at)
        out.collection_status = latest.status
        out.collection_error = redact(latest.error_message)

    out.dynamic_blast_radius = redact(dynamic_blast_radius(incident.events, incident.exposure_start, forensic_tier=incident.forensic_tier, incident_status=incident.status, collection_status=out.collection_status, exposure_end=incident.exposure_end))

    # Compute per-regulation compliance flags from live event data.
    exposure_events = after_exposure(incident.events, incident.exposure_start)
    compliance_events = within_exposure(incident.events, incident.exposure_start, incident.exposure_end) if incident.forensic_tier != 2 else []
    gdpr = check_gdpr_flag(compliance_events)
    pcidss = check_pcidss_flag(compliance_events)
    soc2 = check_soc2_flag(compliance_events)
    out.compliance_review_flags = compliance_review_flags(incident.credential_type, compliance_events, forensic_tier=incident.forensic_tier)
    out.pcidss_flag = pcidss
    out.soc2_flag = soc2
    # Historical rows stored a combined GDPR/PCI flag; recompute from evidence.
    out.gdpr_flag = gdpr
    out.compliance_reasons = build_compliance_reasons(
        gdpr=out.gdpr_flag,
        pcidss=pcidss,
        soc2=soc2,
        events=compliance_events,
    )
    out.financial_impact_lines = [
        FinancialImpactLineOut(**asdict(line))
        for line in compute_financial_impact_lines(within_exposure(incident.events, incident.exposure_start, incident.exposure_end))
    ]
    out.financial_history_lines = [
        FinancialImpactLineOut(**asdict(line))
        for line in compute_financial_impact_lines(incident.events)
    ]
    return add_user_names(out, incident, db)


class RelatedCredentialOut(BaseModel):
    incident_id: str
    credential_type: str
    credential_hint: str
    status: str
    forensic_tier: int
    dismissed: bool


class RelatedCredentialsOut(BaseModel):
    commit_available: bool
    total: int
    offset: int
    items: list[RelatedCredentialOut]


@router.get("/{incident_id}/related-credentials", response_model=RelatedCredentialsOut)
def related_credentials(incident: IncidentRecord = Depends(incident_access), db: Session = Depends(get_db),
                        offset: int = 0, limit: int = 25):
    """Other incidents on the exact commit in this same authorised project."""
    offset, limit = max(0, offset), min(max(1, limit), 100)
    if not incident.commit_hash or not incident.commit_hash.strip():
        return RelatedCredentialsOut(commit_available=False, total=0, offset=offset, items=[])
    query = db.query(IncidentRecord).filter(IncidentRecord.project_id == incident.project_id,
        IncidentRecord.commit_hash == incident.commit_hash, IncidentRecord.incident_id != incident.incident_id)
    rows = query.order_by(IncidentRecord.created_at.asc(), IncidentRecord.incident_id.asc()).offset(offset).limit(limit).all()
    return RelatedCredentialsOut(commit_available=True, total=query.count(), offset=offset,
        items=[RelatedCredentialOut(incident_id=row.incident_id, credential_type=redact(row.credential_type),
            credential_hint=redact(row.credential_hint), status=row.status, forensic_tier=row.forensic_tier,
            dismissed=row.dismissed) for row in rows])


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
    from background_jobs import enqueue
    enqueue(db, 'notification', {'type': 'incident_assigned', 'incident_id': incident.incident_id,
                                 'user_id': target.id, 'channel': 'email'}, project_id=incident.project_id)
    record(db, user, 'incident.assigned', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'assigned_to': target.id})
    db.commit()
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

    from collection_credentials import ReaderConfigurationError, project_reader
    try:
        reader_values = project_reader(db, incident, platform)
    except ReaderConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    if platform == "stripe":
        import config
        from collectors.stripe import _is_usable_key
        reader = reader_values['api_key'] if reader_values is not None else config.STRIPE_API_KEY
        if not _is_usable_key(reader):
            raise HTTPException(status_code=422, detail="Configure a reader key for this Stripe account before refreshing.")
        mode = re.match(r"^(?:sk|rk)_(live|test)_", incident.credential_hint or "")
        if mode and f"_{mode.group(1)}_" not in reader:
            raise HTTPException(status_code=422, detail="The configured Stripe reader key uses a different live/test mode from the detected key.")

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
        "stripe": "Stripe Events query started using the configured reader.",
        "twilio": "Twilio Messages, Calls and Monitor Events query started.",
    }.get(platform, "Log query started.")

    if user is not None and request is not None:
        record(db, user, 'incident.refreshed', request, project_id=incident.project_id, incident_id=incident.incident_id)
    from background_jobs import enqueue
    # Keep the previous evidence visible until a replacement collection succeeds.
    incident.status = 'collecting'
    enqueue(db, 'incident_collect', {'incident_id': incident.incident_id, 'notify': False}, project_id=incident.project_id)
    db.commit()

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


@router.post("/{incident_id}/twilio-account", response_model=RefreshResponse, status_code=202,
             dependencies=[Depends(require_admin_or_lead), Depends(incident_access), Depends(local_operator)])
def associate_twilio_account(incident_id: str, body: TwilioAccountRequest,
                             background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db),
                             user: User = Depends(require_admin_or_lead)):
    """Associate an operator-confirmed account with a detected key and collect its evidence."""
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    if incident.credential_type != "twilio_api_key" or incident.forensic_tier != 2:
        raise HTTPException(400, "Only Twilio API key detections without an account can be associated")
    from collection_credentials import ReaderConfigurationError, project_reader
    import config
    try:
        reader = project_reader(db, incident, 'twilio')
    except ReaderConfigurationError as exc:
        raise HTTPException(422, str(exc)) from None
    account_sid = reader['account_sid'] if reader is not None else config.TWILIO_ACCOUNT_SID
    if not re.fullmatch(r"AC[0-9a-fA-F]{32}", account_sid or "") or body.account_sid.lower() != account_sid.lower():
        raise HTTPException(400, "Account SID must match the configured Twilio reader account")
    incident.principal_id = body.account_sid
    incident.forensic_tier = 1
    incident.unavailable_reason = None
    db.commit()
    return _queue_incident_refresh(incident_id, background_tasks, db, user, request)


@router.post("/{incident_id}/azure-application", response_model=RefreshResponse, status_code=202,
             dependencies=[Depends(require_admin_or_lead), Depends(incident_access), Depends(local_operator)])
def associate_azure_application(incident_id: str, body: AzureApplicationRequest,
                                background_tasks: BackgroundTasks, request: Request,
                                db: Session = Depends(get_db), user: User = Depends(require_admin_or_lead)):
    """Collect application activity after an operator identifies the owning app."""
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    if incident.credential_type != "azure_client_secret" or incident.forensic_tier != 2:
        raise HTTPException(400, "Only Azure client secret detections without an application can be associated")
    from collection_credentials import ReaderConfigurationError, project_reader
    import config
    try:
        reader = project_reader(db, incident, 'azure')
    except ReaderConfigurationError as exc:
        raise HTTPException(422, str(exc)) from None
    if reader is None and not all((config.AZURE_TENANT_ID, config.AZURE_CLIENT_ID, config.AZURE_CLIENT_SECRET, config.AZURE_SUBSCRIPTION_ID)):
        raise HTTPException(422, "Configure the Azure Activity Log reader on the backend before collecting activity")
    incident.principal_id = str(body.client_id)
    incident.forensic_tier = 1
    incident.unavailable_reason = None
    record(db, user, 'incident.azure_application_associated', request, project_id=incident.project_id,
           incident_id=incident.incident_id, detail={'client_id': str(body.client_id)})
    db.commit()
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
