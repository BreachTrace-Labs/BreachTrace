"""
GET  /research/export     — all experiment runs, for the Research page table
GET  /research/platforms  — per-platform comparison, for the headline chart
POST /research/record     — persist one completed experiment run
"""
from __future__ import annotations

import uuid
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Literal, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import AliasChoices, BaseModel, Field, ValidationError, field_validator, model_validator
from sqlalchemy.orm import Session

from auth import require_admin_or_lead
from db.crud import get_incident
from db.database import get_db
from db.models import VALID_PLATFORMS, ExperimentRun, BackgroundJob, User
from redaction import mask_identifier
from research.analysis import compare_platforms, latency_by_platform

router = APIRouter(prefix="/research", tags=["research"])


class GCPHistoricalRequest(BaseModel):
    project_id: str = Field(min_length=1, max_length=36)
    gcp_project_id: str = Field(pattern=r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$')
    principal_email: str = Field(max_length=254)
    scenario_id: str = Field(pattern=r'^GCP-[A-Z0-9-]{2,72}$')
    start_utc: datetime
    end_utc: datetime

    @field_validator('principal_email')
    @classmethod
    def valid_principal(cls, value):
        from detector.patterns import GCP_CLIENT_EMAIL_PATTERN
        if not GCP_CLIENT_EMAIL_PATTERN.fullmatch(value.lower()):
            raise ValueError('Enter a GCP service-account email')
        return value

    @model_validator(mode='after')
    def valid_window(self):
        if self.start_utc.utcoffset() is None or self.end_utc.utcoffset() is None:
            raise ValueError('Start and end require an explicit UTC offset')
        self.start_utc = self.start_utc.astimezone(timezone.utc)
        self.end_utc = self.end_utc.astimezone(timezone.utc)
        if self.end_utc < self.start_utc or self.end_utc - self.start_utc > timedelta(days=90):
            raise ValueError('Choose an ordered range no longer than 90 days')
        if self.end_utc > datetime.now(timezone.utc):
            raise ValueError('The research window cannot end in the future')
        return self


def _gcp_historical_job(job):
    if job is None:
        return None
    return {'id': job.id, 'status': job.status, 'created_at': job.created_at,
            'scenario_id': job.payload.get('scenario_id'), 'error': job.last_error, 'result': job.result}


@router.post('/gcp-historical', status_code=202)
def start_gcp_historical(body: GCPHistoricalRequest, request: Request,
                         db: Session = Depends(get_db), user: User = Depends(require_admin_or_lead)):
    from access import assert_project_access
    from audit import record
    from background_jobs import enqueue
    from collection_credentials import ReaderConfigurationError, project_reader
    from db.models import Project
    from gcp_reader import reader_project_id
    assert_project_access(body.project_id, user, db)
    try:
        reader = project_reader(db, SimpleNamespace(project_id=body.project_id), 'gcp')
        if reader_project_id(reader) != body.gcp_project_id:
            raise ReaderConfigurationError('The configured GCP reader belongs to a different project.')
    except (ReaderConfigurationError, KeyError, ValueError) as exc:
        message = str(exc) if isinstance(exc, ReaderConfigurationError) else 'The GCP reader configuration is invalid.'
        raise HTTPException(422, message) from None
    db.query(Project).filter_by(id=body.project_id).with_for_update().one()
    active = db.query(BackgroundJob).filter(BackgroundJob.kind == 'gcp_historical',
                                             BackgroundJob.project_id == body.project_id,
                                             BackgroundJob.status.in_(['queued', 'running'])).first()
    if active:
        raise HTTPException(409, 'A historical GCP query is already running for this project.')
    payload = body.model_dump(mode='json')
    job = enqueue(db, 'gcp_historical', payload, project_id=body.project_id, max_attempts=1)
    record(db, user, 'research.gcp_historical_started', request, project_id=body.project_id,
           detail={'scenario_id': body.scenario_id, 'start_utc': body.start_utc.isoformat(), 'end_utc': body.end_utc.isoformat()})
    db.commit()
    return _gcp_historical_job(job)


@router.post('/gcp-historical/import', status_code=201)
async def import_gcp_historical(request: Request, project_id: str = Form(...), gcp_project_id: str = Form(...),
                                principal_email: str = Form(...), scenario_id: str = Form(...),
                                start_utc: str = Form(...), end_utc: str = Form(...), evidence: UploadFile = File(...),
                                db: Session = Depends(get_db), user: User = Depends(require_admin_or_lead)):
    from access import assert_project_access
    from audit import record
    from db.models import Project
    from fastapi.encoders import jsonable_encoder
    from research.gcp_import import ImportErrorSafe, MAX_FILE_BYTES, import_export
    assert_project_access(project_id, user, db)
    try:
        body = GCPHistoricalRequest(project_id=project_id, gcp_project_id=gcp_project_id,
                                    principal_email=principal_email, scenario_id=scenario_id,
                                    start_utc=start_utc, end_utc=end_utc)
    except ValidationError:
        raise HTTPException(422, 'Check the project, principal, scenario identifier and UTC range.') from None
    try:
        contents = await evidence.read(MAX_FILE_BYTES + 1)
    finally:
        await evidence.close()
    payload = body.model_dump(mode='json')
    try:
        result = import_export(contents, payload)
    except ImportErrorSafe as exc:
        raise HTTPException(422, str(exc)) from None
    payload['evidence_source'] = 'imported_json'
    payload['source_sha256'] = result['source_sha256']
    key_material = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    dedupe_key = 'gcp-import:' + hashlib.sha256(key_material).hexdigest()
    # Serialize imports for this project before checking the unique key.
    db.query(Project).filter_by(id=project_id).with_for_update().one()
    existing = db.query(BackgroundJob).filter_by(dedupe_key=dedupe_key).first()
    if existing:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=200, content=jsonable_encoder(_gcp_historical_job(existing)))
    job = BackgroundJob(id=str(uuid.uuid4()), kind='gcp_historical', project_id=project_id,
                        payload=payload, result=jsonable_encoder(result), status='complete',
                        max_attempts=1, dedupe_key=dedupe_key)
    db.add(job)
    record(db, user, 'research.gcp_historical_imported', request, project_id=project_id,
           detail={'scenario_id': scenario_id, 'source_sha256': result['source_sha256'], 'record_count': result['record_count']})
    db.commit()
    return _gcp_historical_job(job)


@router.get('/gcp-historical/latest')
def latest_gcp_historical(project_id: str, db: Session = Depends(get_db),
                          user: User = Depends(require_admin_or_lead)):
    from access import assert_project_access
    assert_project_access(project_id, user, db)
    job = db.query(BackgroundJob).filter_by(kind='gcp_historical', project_id=project_id).order_by(BackgroundJob.created_at.desc(), BackgroundJob.id.desc()).first()
    return _gcp_historical_job(job)


@router.get('/gcp-historical/{job_id}')
def get_gcp_historical(job_id: str, db: Session = Depends(get_db),
                       user: User = Depends(require_admin_or_lead)):
    from access import assert_project_access
    job = db.query(BackgroundJob).filter_by(id=job_id, kind='gcp_historical').first()
    if not job or not job.project_id:
        raise HTTPException(404, 'Historical GCP query not found.')
    assert_project_access(job.project_id, user, db)
    return _gcp_historical_job(job)


class GCPGroundTruthMapping(BaseModel):
    unit: Literal['commands', 'audit_records']
    command_column: str | None = Field(default=None, max_length=80, pattern=r'^[\w .-]+$')
    record_id_column: str | None = Field(default=None, max_length=80, pattern=r'^[\w .-]+$')
    category_column: str | None = Field(default=None, max_length=80, pattern=r'^[\w .-]+$')
    outcome_column: str | None = Field(default=None, max_length=80, pattern=r'^[\w .-]+$')

    @model_validator(mode='after')
    def complete_mapping(self):
        if self.unit == 'commands' and (not self.command_column or self.record_id_column or self.category_column or self.outcome_column):
            raise ValueError('Choose the command column only')
        if self.unit == 'audit_records' and (self.command_column or not self.record_id_column or not (self.category_column or self.outcome_column)):
            raise ValueError('Choose the insert ID and at least one label column')
        used = [x for x in (self.command_column, self.record_id_column, self.category_column, self.outcome_column) if x]
        if len(set(used)) != len(used):
            raise ValueError('Choose different columns for each field')
        return self


def _historical_evidence(job_id: str, db: Session, user: User):
    from access import assert_project_access
    job = db.query(BackgroundJob).filter_by(id=job_id, kind='gcp_historical', status='complete').first()
    if not job or not job.project_id:
        raise HTTPException(404, 'Completed historical GCP evidence not found.')
    assert_project_access(job.project_id, user, db)
    if not isinstance(job.result, dict) or job.result.get('mode') != 'research_forensic_evaluation' or not isinstance(job.result.get('events'), list):
        raise HTTPException(422, 'Historical evidence is not available for evaluation.')
    return job


@router.post('/gcp-historical/{job_id}/evaluate', status_code=201)
async def evaluate_gcp_historical(job_id: str, request: Request, unit: str = Form(...),
                                  command_column: str | None = Form(None), record_id_column: str | None = Form(None),
                                  category_column: str | None = Form(None), outcome_column: str | None = Form(None),
                                  ground_truth: UploadFile = File(...), db: Session = Depends(get_db),
                                  user: User = Depends(require_admin_or_lead)):
    from audit import record
    from db.models import Project
    from fastapi.encoders import jsonable_encoder
    from research.gcp_ground_truth import GroundTruthError, MAX_CSV_BYTES, evaluate
    evidence_job = _historical_evidence(job_id, db, user)
    try:
        mapping = GCPGroundTruthMapping(unit=unit, command_column=command_column or None,
                                        record_id_column=record_id_column or None,
                                        category_column=category_column or None, outcome_column=outcome_column or None)
    except ValidationError:
        raise HTTPException(422, 'Choose valid, distinct CSV column names for the selected row type.') from None
    try:
        contents = await ground_truth.read(MAX_CSV_BYTES + 1)
    finally:
        await ground_truth.close()
    try:
        result = evaluate(contents, evidence_job.result, mapping.model_dump())
    except GroundTruthError as exc:
        raise HTTPException(422, str(exc)) from None
    result.update({'mode': 'research_ground_truth_comparison', 'evidence_job_id': job_id,
                   'scenario_id': evidence_job.payload.get('scenario_id'),
                   'evidence_source': evidence_job.result.get('evidence_source'),
                   'evidence_sha256': evidence_job.result.get('source_sha256')})
    payload = {'evidence_job_id': job_id, 'source_sha256': result['source_sha256'], 'mapping': mapping.model_dump()}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    key = 'gcp-eval:' + digest
    db.query(Project).filter_by(id=evidence_job.project_id).with_for_update().one()
    existing = db.query(BackgroundJob).filter_by(dedupe_key=key).first()
    if existing:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=200, content=jsonable_encoder({'id': existing.id, 'result': existing.result}))
    evaluation = BackgroundJob(id=str(uuid.uuid4()), kind='gcp_ground_truth', project_id=evidence_job.project_id,
                               payload=payload, result=jsonable_encoder(result), status='complete', max_attempts=1, dedupe_key=key)
    db.add(evaluation)
    record(db, user, 'research.gcp_ground_truth_compared', request, project_id=evidence_job.project_id,
           detail={'evidence_job_id': job_id, 'source_sha256': result['source_sha256'], 'unit': mapping.unit, 'rows': result['csv_row_count']})
    db.commit()
    return {'id': evaluation.id, 'result': evaluation.result}


@router.get('/gcp-historical/{job_id}/evaluation/latest')
def latest_gcp_evaluation(job_id: str, db: Session = Depends(get_db), user: User = Depends(require_admin_or_lead)):
    evidence_job = _historical_evidence(job_id, db, user)
    job = (db.query(BackgroundJob)
           .filter_by(kind='gcp_ground_truth', project_id=evidence_job.project_id, status='complete')
           .filter(BackgroundJob.payload['evidence_job_id'].as_string() == job_id)
           .order_by(BackgroundJob.created_at.desc(), BackgroundJob.id.desc()).first())
    return {'id': job.id, 'result': job.result} if job else None


class BenchmarkRequest(BaseModel):
    models: list[str] = Field(min_length=1, max_length=4)
    cases: int = Field(default=4, ge=1, le=12)
    seed: int = Field(default=20261103, ge=0, le=2147483647)

    @field_validator('models')
    @classmethod
    def validate_models(cls, values):
        if len(set(values)) != len(values) or any(not v.strip() or len(v) > 200 or any(c in v for c in '\r\n') for v in values):
            raise ValueError('Select distinct installed model names')
        return values


def installed_ollama_models():
    import requests
    try:
        session = requests.Session()
        session.trust_env = False
        response = session.get('http://127.0.0.1:11434/api/tags', timeout=5, allow_redirects=False)
        response.raise_for_status()
        models = response.json()['models']
        return [{'name': row['name'], 'size': row.get('size'), 'digest': row.get('digest')} for row in models if isinstance(row, dict) and isinstance(row.get('name'), str)]
    except Exception:
        raise HTTPException(503, 'Local Ollama is unavailable. Start Ollama and install models before comparing.') from None


@router.get('/model-benchmark/models')
def benchmark_models(request: Request):
    from routers.settings import local_operator
    local_operator(request)
    return {'models': installed_ollama_models()}


@router.post('/model-benchmark', status_code=202)
def start_model_benchmark(body: BenchmarkRequest, request: Request, db: Session = Depends(get_db)):
    from routers.settings import local_operator
    from background_jobs import enqueue
    local_operator(request)
    available = {model['name'] for model in installed_ollama_models()}
    if not set(body.models).issubset(available):
        raise HTTPException(422, 'Every selected model must already be installed in local Ollama.')
    existing = db.query(BackgroundJob).filter(BackgroundJob.kind == 'model_benchmark', BackgroundJob.status.in_(['queued', 'running'])).first()
    if existing:
        raise HTTPException(409, 'A model comparison is already running.')
    job = enqueue(db, 'model_benchmark', {'models': body.models, 'cases': body.cases, 'seed': body.seed}, max_attempts=1)
    db.commit()
    return {'id': job.id, 'status': job.status}


@router.get('/model-benchmark/latest')
def latest_model_benchmark(request: Request, db: Session = Depends(get_db)):
    from routers.settings import local_operator
    local_operator(request)
    job = db.query(BackgroundJob).filter_by(kind='model_benchmark').order_by(BackgroundJob.created_at.desc()).first()
    return {'id': job.id, 'status': job.status, 'result': job.result, 'error': job.last_error, 'created_at': job.created_at} if job else None


class ExperimentRunOut(BaseModel):
    run_id: str = Field(validation_alias="id")
    access_key_id: Optional[str]
    # Float, not int: the harness measures to one decimal and truncating
    # 1.4s -> 1s is a ~30% error on the fastest platform.
    detection_time_s: Optional[float]
    report_time_s: Optional[float]
    api_calls: list[str]
    expected_severity: Optional[str]
    actual_severity: Optional[str]
    status: Optional[str]
    created_at: datetime
    # Without these the Research page's per-platform comparison — the paper's
    # headline result — has no data source. compare_platforms() groups on
    # `platform` and reads `first_external_use_s` / `event_count`.
    platform: str = "aws"
    run_number: Optional[int] = None
    experiment_group: Optional[str] = None
    first_external_use_s: Optional[float] = None
    external_use_detected: bool = False
    event_count: int = 0

    class Config:
        from_attributes = True
        populate_by_name = True


@router.get("/export", response_model=list[ExperimentRunOut])
def export_experiment_runs(db: Session = Depends(get_db)):
    """Return all experiment runs, ordered by run number, for the Research page."""
    try:
        runs = db.query(ExperimentRun).order_by(ExperimentRun.run_number).all()
    except Exception:
        return []
    result: list[ExperimentRunOut] = []
    for run in runs:
        try:
            incident = run.incident
            result.append(
                ExperimentRunOut(
                    id=run.id,
                    access_key_id=mask_identifier(incident.access_key_id) if incident else None,
                    detection_time_s=run.detection_time_s,
                    report_time_s=run.report_time_s,
                    api_calls=run.api_calls_made or [],
                    expected_severity=None,
                    actual_severity=run.overall_severity,
                    status=incident.status if incident else None,
                    created_at=run.created_at,
                    platform=run.platform or "aws",
                    run_number=run.run_number,
                    experiment_group=run.experiment_group,
                    first_external_use_s=run.first_external_use_s,
                    external_use_detected=bool(run.external_use_detected),
                    event_count=len(incident.events) if incident else 0,
                )
            )
        except Exception:
            continue
    return result


@router.get("/platforms")
def compare_platforms_endpoint(db: Session = Depends(get_db)):
    """
    Per-platform experiment statistics — the paper's headline comparison and
    the Research page's grouped latency chart.

    Serves the analysis functions directly rather than making the frontend
    re-derive statistics from raw rows, so the chart and the paper table are
    guaranteed to quote the same numbers.
    """
    try:
        runs = db.query(ExperimentRun).all()
    except Exception:
        runs = []

    run_dicts = [
        {
            "platform": run.platform or "aws",
            "detection_time_s": run.detection_time_s,
            "report_time_s": run.report_time_s,
            "first_external_use_s": run.first_external_use_s,
            "overall_severity": run.overall_severity,
            "experiment_group": run.experiment_group,
            # `status` drives completion_rate; the incident is the source of truth.
            "status": run.incident.status if run.incident else None,
            "event_count": len(run.incident.events) if run.incident else 0,
        }
        for run in runs
    ]

    return {
        "total_runs": len(run_dicts),
        "by_platform": compare_platforms(run_dicts),
        # Platforms with no timing data are omitted rather than reported as 0.0
        # so an unprovisioned platform cannot read as an instantaneous one.
        "detection_latency_by_platform": latency_by_platform(run_dicts),
    }


# ---------------------------------------------------------------------------
# POST /research/record — the write path
#
# Until this existed, nothing in the codebase ever constructed an ExperimentRun.
# The table was never written to, so /export and /platforms always returned
# empty against a live backend and the Research page had no data source at all.
# ---------------------------------------------------------------------------

class ExperimentRunIn(BaseModel):
    """
    One completed experiment run, as posted by research/harness.py.

    Accepts both field spellings the codebase already tolerates: the harness
    emits `first_use_time_s` / `api_calls`, the DB uses `first_external_use_s` /
    `api_calls_made`. analysis.py already reads either, so rejecting one here
    would make the recorder stricter than the analysis it feeds.
    """

    incident_id: Optional[str] = None
    run_number: Optional[int] = None
    experiment_group: Optional[str] = None       # 'A' | 'B' | 'C'
    platform: str = "aws"
    exposure_start: Optional[datetime] = None
    attacker_sim_start: Optional[datetime] = None
    detection_time_s: Optional[float] = None
    report_time_s: Optional[float] = None
    first_external_use_s: Optional[float] = Field(
        None,
        validation_alias=AliasChoices("first_external_use_s", "first_use_time_s"),
    )
    api_calls_made: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("api_calls_made", "api_calls"),
    )
    impact_categories: list[str] = Field(default_factory=list)
    overall_severity: Optional[str] = None
    external_use_detected: bool = False
    notes: Optional[str] = None

    class Config:
        populate_by_name = True

    @field_validator("platform", mode="before")
    @classmethod
    def _normalise_platform(cls, value: object) -> str:
        """
        experiment_runs.platform has no CHECK constraint — the migration added
        one only to forensic_events and collection_status. A typo would create a
        phantom platform bar in the paper's headline figure, so validate here.
        """
        platform = str(value or "aws").strip().lower()
        if platform not in VALID_PLATFORMS:
            raise ValueError(
                f"Unknown platform {platform!r}. Expected one of: {', '.join(VALID_PLATFORMS)}"
            )
        return platform

    @field_validator("overall_severity", mode="before")
    @classmethod
    def _normalise_severity(cls, value: object) -> Optional[str]:
        """compare_platforms() and /incidents/stats both uppercase; match them
        so one campaign cannot produce both 'High' and 'HIGH' buckets."""
        if value is None:
            return None
        return str(value).strip().upper() or None


def _next_run_number(existing: list[int]) -> int:
    """Next sequential run number. Pure, so it is testable without a session."""
    numbers = [n for n in existing if isinstance(n, int)]
    return (max(numbers) + 1) if numbers else 1


@router.post("/record", response_model=ExperimentRunOut, status_code=201)
def record_experiment_run(body: ExperimentRunIn, db: Session = Depends(get_db)):
    """
    Persist one completed experiment run.

    Unlike /export and /platforms this deliberately does **not** swallow
    exceptions. A read that fails soft degrades a chart; a write that fails soft
    is how a 150-run campaign finishes with an empty table and nobody notices
    until analysis time.
    """
    incident = None
    if body.incident_id:
        incident = get_incident(db, body.incident_id)
        if incident is None:
            # Refusing the orphan rather than storing it: /export derives
            # event_count from the linked incident, so a null link would
            # contribute a real-looking 0 to the paper's events_collected stats.
            raise HTTPException(
                status_code=404,
                detail=f"Incident {body.incident_id!r} not found — refusing to record an orphan run",
            )

    # Upsert on incident_id. Sprint 4 calls for resume-after-failure across a
    # 150-run loop; without this a retried run double-counts total_runs.
    run: ExperimentRun | None = None
    if body.incident_id:
        run = (
            db.query(ExperimentRun)
            .filter(ExperimentRun.incident_id == body.incident_id)
            .first()
        )

    if run is None:
        run = ExperimentRun(id=str(uuid.uuid4()))
        db.add(run)

    run.incident_id = body.incident_id
    if body.run_number is not None:
        run.run_number = body.run_number
    elif run.run_number is None:
        run.run_number = _next_run_number(
            [row[0] for row in db.query(ExperimentRun.run_number).all()]
        )
    run.experiment_group = body.experiment_group
    run.platform = body.platform
    run.exposure_start = body.exposure_start
    run.attacker_sim_start = body.attacker_sim_start
    run.detection_time_s = body.detection_time_s
    run.report_time_s = body.report_time_s
    run.first_external_use_s = body.first_external_use_s
    run.api_calls_made = body.api_calls_made
    run.impact_categories = body.impact_categories
    run.overall_severity = body.overall_severity
    run.external_use_detected = body.external_use_detected
    run.notes = body.notes

    db.commit()
    db.refresh(run)

    return ExperimentRunOut(
        run_id=run.id,
        access_key_id=incident.access_key_id if incident else None,
        detection_time_s=run.detection_time_s,
        report_time_s=run.report_time_s,
        api_calls=run.api_calls_made or [],
        expected_severity=None,
        actual_severity=run.overall_severity,
        status=incident.status if incident else None,
        created_at=run.created_at,
        platform=run.platform or "aws",
        run_number=run.run_number,
        experiment_group=run.experiment_group,
        first_external_use_s=run.first_external_use_s,
        external_use_detected=bool(run.external_use_detected),
        event_count=len(incident.events) if incident else 0,
    )
