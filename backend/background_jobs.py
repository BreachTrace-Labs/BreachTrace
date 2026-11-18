"""Database-backed jobs with leases, bounded retries, and sanitized errors."""
from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from db.database import SessionLocal
from db.models import BackgroundJob

logger = logging.getLogger(__name__)
_LEASE = timedelta(minutes=2)
_stop = threading.Event()
_threads: list[threading.Thread] = []


def enqueue(db: Session, kind: str, payload: dict, *, project_id: str | None = None,
            dedupe_key: str | None = None, max_attempts: int = 3) -> BackgroundJob:
    """Add to the caller's transaction. Callers commit the business change too."""
    job = BackgroundJob(id=str(uuid.uuid4()), kind=kind, project_id=project_id, payload=payload,
                        dedupe_key=dedupe_key, max_attempts=max_attempts)
    db.add(job)
    db.flush()
    return job


def claim(db: Session) -> tuple[str, str] | None:
    now = datetime.now(timezone.utc)
    due = or_(and_(BackgroundJob.status == 'queued', BackgroundJob.available_at <= now),
              and_(BackgroundJob.status == 'running', BackgroundJob.lease_until < now))
    # PostgreSQL workers skip rows already claimed by another transaction.
    job = (db.query(BackgroundJob).filter(due).order_by(BackgroundJob.available_at, BackgroundJob.created_at)
           .with_for_update(skip_locked=True).first())
    if job is None:
        db.rollback()
        return None
    if job.attempts >= job.max_attempts:
        job.status, job.last_error, job.updated_at = 'failed', 'Work stopped after repeated interruptions.', now
        job.lease_token, job.lease_until = None, None
        db.commit()
        return None
    token = str(uuid.uuid4())
    job.status, job.lease_token, job.lease_until = 'running', token, now + _LEASE
    job.attempts += 1
    job.updated_at = now
    job_id = job.id
    db.commit()
    return job_id, token


def _heartbeat(job_id: str, token: str, done: threading.Event) -> None:
    while not done.wait(30):
        with SessionLocal() as db:
            try:
                db.query(BackgroundJob).filter_by(id=job_id, status='running', lease_token=token).update(
                    {'lease_until': datetime.now(timezone.utc) + _LEASE}, synchronize_session=False)
                db.commit()
            except Exception:
                db.rollback()
                logger.warning('Background job lease renewal failed (%s)', job_id)


def process_one() -> bool:
    with SessionLocal() as db:
        claimed = claim(db)
    if not claimed:
        return False
    job_id, token = claimed
    done = threading.Event()
    heartbeat = threading.Thread(target=_heartbeat, args=(job_id, token, done), daemon=True)
    heartbeat.start()
    try:
        with SessionLocal() as db:
            job = db.get(BackgroundJob, job_id)
            kind, payload = job.kind, dict(job.payload)
        result = dispatch(kind, payload)
        error = None
    except Exception as exc:
        # Exceptions can contain URLs, credentials, or provider responses.
        logger.warning('Background job %s failed (%s)', job_id, type(exc).__name__)
        result, error = None, 'The operation failed. Check configuration and provider connectivity.'
    finally:
        done.set()
    with SessionLocal() as db:
        job = db.query(BackgroundJob).filter_by(id=job_id, status='running', lease_token=token).first()
        if job is None:
            return True
        now = datetime.now(timezone.utc)
        job.lease_token, job.lease_until, job.updated_at = None, None, now
        if error is None:
            job.status, job.result, job.last_error = 'complete', result, None
        elif job.attempts < job.max_attempts:
            job.status, job.last_error = 'queued', error
            job.available_at = now + timedelta(seconds=min(300, 10 * 2 ** (job.attempts - 1)))
        else:
            job.status, job.last_error = 'failed', error
        if job.kind == 'wallet_verify' and job.status == 'queued':
            from db.models import CredentialWalletEntry
            entry = db.get(CredentialWalletEntry, job.payload.get('entry_id'))
            if entry is not None and entry.iv == job.payload.get('iv'):
                entry.verification_status = 'pending'
        if job.kind == 'notification' and job.payload.get('type') == 'welcome' and job.status == 'complete':
            job.payload = {key: value for key, value in job.payload.items() if key not in ('ciphertext', 'iv')}
        db.commit()
    return True


def dispatch(kind: str, payload: dict) -> dict:
    if kind == 'snapshot':
        from repository_snapshot import scan_github
        return scan_github(payload['repo_url'])
    if kind == 'wallet_verify':
        from wallet_verify import verify_entry
        if not verify_entry(payload['entry_id'], payload['iv'], payload.get('actor_id')):
            raise RuntimeError('Wallet verification failed')
        return {}
    if kind == 'incident_collect':
        from db.models import IncidentRecord
        from pipeline import run_collection_pipeline
        with SessionLocal() as db:
            incident = db.get(IncidentRecord, payload['incident_id'])
            if incident is None:
                return {'outcome': 'skipped'}
            platform = incident.platform
            credential = incident.access_key_id if platform == 'aws' else incident.principal_id
            if not credential:
                raise ValueError('Incident has no provider identity')
            start = incident.exposure_start
            incident_id = incident.incident_id
        run_collection_pipeline(incident_id, credential, start, platform=platform, refresh_existing=True)
        if payload.get('notify'):
            from notifications import notify_incident_created_by_id
            notify_incident_created_by_id(incident_id)
        return {}
    if kind == 'incident_index':
        from rag.index import index_incident
        with SessionLocal() as db:
            index_incident(db, payload['incident_id'])
        return {}
    if kind == 'incident_notify':
        from notifications import notify_incident_created_by_id
        notify_incident_created_by_id(payload['incident_id'])
        return {}
    if kind == 'notification':
        from notifications import deliver_job
        return {'outcome': deliver_job(payload)}
    raise ValueError('Unsupported background job type')


def _loop() -> None:
    last_cleanup = 0.0
    while not _stop.is_set():
        try:
            import time
            if time.monotonic() - last_cleanup > 60:
                _purge_expired_welcome_secrets()
                last_cleanup = time.monotonic()
            if not process_one():
                _stop.wait(1)
        except Exception as exc:
            logger.warning('Background worker unavailable (%s)', type(exc).__name__)
            _stop.wait(5)


def _purge_expired_welcome_secrets() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    with SessionLocal() as db:
        rows = (db.query(BackgroundJob).filter(BackgroundJob.kind == 'notification',
                BackgroundJob.project_id.is_(None), BackgroundJob.status.in_(['failed', 'queued']),
                BackgroundJob.created_at < cutoff).all())
        for job in rows:
            if job.payload.get('type') == 'welcome' and 'ciphertext' in job.payload:
                job.payload = {key: value for key, value in job.payload.items() if key not in ('ciphertext', 'iv')}
                job.status = 'failed'
                job.last_error = 'Welcome email expired. Share the temporary password securely or create a new invitation.'
        db.commit()


def start_workers() -> None:
    if any(thread.is_alive() for thread in _threads):
        return
    _stop.clear()
    _threads.clear()
    for index in range(2):
        thread = threading.Thread(target=_loop, name=f'background-worker-{index}', daemon=True)
        _threads.append(thread)
        thread.start()


def stop_workers() -> None:
    _stop.set()
