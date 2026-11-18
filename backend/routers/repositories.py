"""Persistent snapshot scan jobs for the local operator."""
from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from audit import record
from auth import require_admin_or_lead
from background_jobs import enqueue
from db.database import get_db
from db.models import BackgroundJob, User
from repository_snapshot import repository_name
from routers.settings import local_operator

router = APIRouter(prefix='/repositories', tags=['repositories'], dependencies=[Depends(local_operator)])


class ScanRequest(BaseModel):
    repo_url: str = Field(max_length=300)

    @field_validator('repo_url')
    @classmethod
    def valid_repo(cls, value):
        repository_name(value)
        return value


@router.post('/scan', status_code=202)
def start_scan(body: ScanRequest, request: Request,
               user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    job = enqueue(db, 'snapshot', {'repo_url': body.repo_url}, max_attempts=3)
    record(db, user, 'snapshot.started', request, detail={'repository': repository_name(body.repo_url)})
    db.commit()
    return {'scan_id': job.id, 'status': 'queued'}


@router.get('/scans/{scan_id}')
def scan_status(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.query(BackgroundJob).filter_by(id=str(scan_id), kind='snapshot').first()
    if job is None:
        raise HTTPException(404, 'Scan not found')
    return {'scan_id': job.id, 'status': 'scanning' if job.status == 'running' else job.status,
            'result': job.result, 'error': job.last_error if job.status == 'failed' else None,
            'attempts': job.attempts, 'max_attempts': job.max_attempts}
