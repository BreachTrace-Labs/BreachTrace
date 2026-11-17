"""Local operator snapshot scans; no cloud forensics on discovered candidates."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import threading
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from audit import record
from auth import require_admin_or_lead
from db.database import get_db
from db.models import User
from repository_snapshot import repository_name, scan_github
from routers.settings import local_operator

router = APIRouter(prefix="/repositories", tags=["repositories"], dependencies=[Depends(local_operator)])
_lock = threading.Lock()
_jobs: dict[str, dict] = {}
_slots = threading.BoundedSemaphore(1)


class ScanRequest(BaseModel):
    repo_url: str = Field(max_length=300)

    @field_validator("repo_url")
    @classmethod
    def valid_repo(cls, value):
        repository_name(value)
        return value


def run_scan(job_id: str):
    try:
        with _lock:
            _jobs[job_id]["status"] = "scanning"
            url = _jobs[job_id]["repo_url"]
        result = scan_github(url)
        with _lock:
            _jobs[job_id].update(status="complete", result=result)
    except Exception:
        # No exception string: URLs may contain temporary archive credentials.
        with _lock:
            _jobs[job_id].update(status="failed", error="Snapshot scan failed. Check GitHub access, repository size and configured limits.")
    finally:
        with _lock:
            record = deepcopy(_jobs[job_id])
        try:
            folder = Path(__file__).resolve().parents[2] / "data" / "repository-scans"
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / (job_id + ".json")
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump(record, output, indent=2)
        except OSError:
            with _lock:
                _jobs[job_id]["evidence_save_failed"] = True
        finally:
            _slots.release()


@router.post("/scan", status_code=202)
def start_scan(body: ScanRequest, tasks: BackgroundTasks, request: Request,
               user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    if not _slots.acquire(blocking=False):
        raise HTTPException(409, "A repository scan is already running")
    try:
        record(db, user, 'snapshot.started', request, detail={'repository': repository_name(body.repo_url)})
        db.commit()
    except Exception:
        db.rollback()
        _slots.release()
        raise
    job_id = str(uuid.uuid4())
    with _lock:
        # Bound process memory. Evidence persists under data/repository-scans.
        while len(_jobs) >= 20:
            oldest = next(iter(_jobs))
            _jobs.pop(oldest)
        _jobs[job_id] = {"scan_id": job_id, "repo_url": body.repo_url, "status": "queued",
                         "created_at": datetime.now(timezone.utc).isoformat()}
    tasks.add_task(run_scan, job_id)
    return {"scan_id": job_id, "status": "queued"}


@router.get("/scans/{scan_id}")
def scan_status(scan_id: uuid.UUID):
    with _lock:
        job = _jobs.get(str(scan_id))
        if job is None:
            raise HTTPException(404, "Scan not found in this backend process")
        return deepcopy(job)
