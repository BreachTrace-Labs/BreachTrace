"""Persistent snapshot scan jobs for the local operator."""
from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from audit import record
from access import assert_project_access
from auth import require_admin_or_lead
from background_jobs import enqueue
from db.database import get_db
from db.models import BackgroundJob, IncidentRecord, Project, User
from db.crud import create_incident, finalize_non_forensic_incident
from repository_snapshot import repository_name
from routers.settings import local_operator

router = APIRouter(prefix='/repositories', tags=['repositories'], dependencies=[Depends(local_operator)])
SNAPSHOT_REASON = ('Snapshot observation: The candidate was found in the scanned revision; its first exposure time is unknown. '
                   'The snapshot stores a masked hint only, so provider activity has not been collected. '
                   'Review the source and provider records before drawing conclusions.')


class ScanRequest(BaseModel):
    repo_url: str = Field(max_length=300)

    @field_validator('repo_url')
    @classmethod
    def valid_repo(cls, value):
        repository_name(value)
        return value


class AddFindingRequest(BaseModel):
    project_id: str


def _project_for_scan(db, user, project_id, result):
    project = assert_project_access(project_id, user, db)
    if repository_name(result.get('repo_url', '')).lower() != (project.github_repo_full_name or '').lower():
        raise HTTPException(400, 'Select the project connected to this scanned repository.')
    return project


def _possible_matches(db, project_id, findings):
    rows = db.query(IncidentRecord).filter_by(project_id=project_id).all()
    by_hint = {}
    for row in rows:
        by_hint.setdefault((row.credential_type, row.credential_hint), row.incident_id)
    return {finding['fingerprint']: by_hint[(finding.get('credential_type'), finding.get('credential_hint'))]
            for finding in findings if (finding.get('credential_type'), finding.get('credential_hint')) in by_hint}


@router.post('/scan', status_code=202)
def start_scan(body: ScanRequest, request: Request,
               user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    job = enqueue(db, 'snapshot', {'repo_url': body.repo_url}, max_attempts=3)
    record(db, user, 'snapshot.started', request, detail={'repository': repository_name(body.repo_url)})
    db.commit()
    return {'scan_id': job.id, 'status': 'queued'}


@router.get('/scans/{scan_id}')
def scan_status(scan_id: uuid.UUID, project_id: str | None = None,
                user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    job = db.query(BackgroundJob).filter_by(id=str(scan_id), kind='snapshot').first()
    if job is None:
        raise HTTPException(404, 'Scan not found')
    possible_matches = {}
    project_compatible = False
    if project_id and job.result:
        project = assert_project_access(project_id, user, db)
        project_compatible = repository_name(job.result.get('repo_url', '')).lower() == (project.github_repo_full_name or '').lower()
        if project_compatible:
            possible_matches = _possible_matches(db, project.id, job.result.get('findings', []))
    return {'scan_id': job.id, 'status': 'scanning' if job.status == 'running' else job.status,
            'result': job.result, 'error': job.last_error if job.status == 'failed' else None,
            'attempts': job.attempts, 'max_attempts': job.max_attempts, 'possible_matches': possible_matches,
            'project_compatible': project_compatible}


@router.post('/scans/{scan_id}/findings/{fingerprint}/incident', status_code=201)
def add_finding(scan_id: uuid.UUID, fingerprint: str, body: AddFindingRequest, request: Request,
                user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    job = db.query(BackgroundJob).filter_by(id=str(scan_id), kind='snapshot', status='complete').first()
    if job is None or not isinstance(job.result, dict):
        raise HTTPException(404, 'Completed scan not found.')
    project = _project_for_scan(db, user, body.project_id, job.result)
    # Serialize concurrent additions for this project before the duplicate check.
    db.query(Project).filter_by(id=project.id).with_for_update().one()
    findings = [finding for finding in job.result.get('findings', []) if finding.get('fingerprint') == fingerprint]
    if len(findings) != 1:
        raise HTTPException(404, 'Scan finding not found or ambiguous.')
    finding = findings[0]
    if _possible_matches(db, project.id, [finding]):
        raise HTTPException(409, 'A possible matching incident already exists. Review it in Monitor; masked hints cannot prove two keys are identical.')
    incident = create_incident(db, credential_type=finding['credential_type'], credential_hint=finding['credential_hint'],
        repo_url=job.result['repo_url'], commit_hash=job.result.get('revision'),
        exposure_start=job.updated_at, forensic_tier=2, unavailable_reason=SNAPSHOT_REASON,
        project_id=project.id, commit=False)
    enqueue(db, 'incident_index', {'incident_id': incident.incident_id}, project_id=project.id)
    record(db, user, 'snapshot.finding_added', request, project_id=project.id, incident_id=incident.incident_id,
           detail={'scan_id': str(scan_id), 'fingerprint': fingerprint})
    finalize_non_forensic_incident(db, incident.incident_id, SNAPSHOT_REASON)
    return {'incident_id': incident.incident_id, 'message': 'Added for review. Exposure time is unknown; provider collection has not started.'}
