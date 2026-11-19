"""Organisation and team administration."""
from typing import Literal
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import get_active_user, hash_password, require_admin, require_admin_or_lead
from audit import public as audit_public, record
from db.database import get_db
from db.models import AuditLog, BackgroundJob, Organisation, User

router = APIRouter(prefix="/org", tags=["organisation"])


class OrgUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AutoRefreshInput(BaseModel):
    enabled: bool
    interval_minutes: int = Field(ge=15, le=10080)


def _refresh_settings(job):
    if job is None:
        return {'enabled': False, 'interval_minutes': 60, 'next_run_at': None, 'status': 'disabled', 'last_run': None, 'error': None}
    enabled = bool(job.payload.get('enabled'))
    return {'enabled': enabled, 'interval_minutes': job.payload.get('interval_minutes', 60),
            'next_run_at': job.available_at if enabled and job.status == 'queued' else None,
            'status': job.status if enabled else 'disabled', 'last_run': job.result, 'error': job.last_error}


@router.get('/auto-refresh')
def get_auto_refresh(user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    job = db.query(BackgroundJob).filter_by(dedupe_key=f'auto-refresh:{user.organisation_id}').first()
    return _refresh_settings(job)


@router.put('/auto-refresh')
def set_auto_refresh(body: AutoRefreshInput, request: Request, user: User = Depends(require_admin_or_lead),
                     db: Session = Depends(get_db)):
    if body.enabled:
        raise HTTPException(410, 'Set automatic refresh on each incident instead.')
    now = datetime.now(timezone.utc)
    key = f'auto-refresh:{user.organisation_id}'
    job = db.query(BackgroundJob).filter_by(dedupe_key=key).with_for_update().first()
    if job is None:
        job = BackgroundJob(kind='auto_refresh', dedupe_key=key, project_id=None)
        db.add(job)
    job.payload = {'organisation_id': user.organisation_id, 'enabled': body.enabled,
                   'interval_minutes': body.interval_minutes}
    job.updated_at = now
    if job.status != 'running':
        job.status = 'queued' if body.enabled else 'complete'
        job.attempts = 0
        job.last_error = None
        job.available_at = now + timedelta(minutes=body.interval_minutes)
        job.lease_token = job.lease_until = None
    record(db, user, 'organisation.auto_refresh_updated', request,
           detail={'enabled': body.enabled, 'interval_minutes': body.interval_minutes})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Schedule was changed concurrently. Reload and try again.') from None
    return _refresh_settings(job)


class Invite(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    role: Literal["security_lead", "developer"]
    sign_in_method: Literal["password", "github"] = "password"
    temporary_password: str | None = Field(default=None, min_length=10, max_length=72)


class UserUpdate(BaseModel):
    role: Literal["security_lead", "developer"] | None = None
    is_active: bool | None = None


def user_data(user: User):
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role,
            "is_active": user.is_active, "last_login_at": user.last_login_at}


@router.get("")
def get_org(user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    org = db.get(Organisation, user.organisation_id)
    if org is None:
        raise HTTPException(404, "Organisation not found")
    return {"id": org.id, "name": org.name, "slug": org.slug, "created_at": org.created_at}


@router.put("")
def update_org(body: OrgUpdate, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "Organisation name cannot be empty")
    org = db.get(Organisation, user.organisation_id)
    org.name = name
    record(db, user, "organisation.updated", request)
    db.commit()
    return {"id": org.id, "name": org.name, "slug": org.slug}


@router.get("/users")
def list_users(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [user_data(row) for row in db.query(User).filter_by(organisation_id=user.organisation_id).order_by(User.email).all()]


@router.get("/audit")
def list_audit(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
               action: str | None = None, user_id: str | None = None, project_id: str | None = None,
               date_from: datetime | None = None, date_to: datetime | None = None,
               user: User = Depends(require_admin), db: Session = Depends(get_db)):
    query = db.query(AuditLog, User.full_name).outerjoin(User, User.id == AuditLog.actor_user_id).filter(AuditLog.organisation_id == user.organisation_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if user_id:
        query = query.filter(AuditLog.actor_user_id == user_id)
    if project_id:
        query = query.filter(AuditLog.project_id == project_id)
    if date_from:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AuditLog.created_at <= date_to)
    return [audit_public(entry, name) for entry, name in query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset(offset).limit(limit).all()]


@router.post("/users/invite", status_code=201)
def invite(body: Invite, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    name = body.full_name.strip()
    if not name:
        raise HTTPException(422, "Full name cannot be empty")
    if body.sign_in_method == 'github':
        from routers.auth import github_oauth_config
        if not github_oauth_config():
            raise HTTPException(503, 'GitHub sign-in is not configured. Configure GitHub OAuth before inviting GitHub users.')
        if body.temporary_password is not None:
            raise HTTPException(422, 'GitHub invitations do not use a temporary password')
        password = None
    else:
        if body.temporary_password is None:
            raise HTTPException(422, 'A temporary password is required for password invitations')
        try:
            password = hash_password(body.temporary_password)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
    target = User(organisation_id=user.organisation_id, email=body.email.lower(), full_name=name,
                  role=body.role, hashed_password=password, must_change_password=body.sign_in_method == 'password')
    db.add(target)
    try:
        db.flush()
        from background_jobs import enqueue
        payload = {'type': 'welcome', 'channel': 'email', 'user_id': target.id, 'method': body.sign_in_method}
        if body.sign_in_method == 'password':
            from crypto import encrypt_blob
            try:
                ciphertext, iv = encrypt_blob({'temporary_password': body.temporary_password})
            except Exception:
                raise HTTPException(503, 'Configure wallet encryption before inviting users') from None
            payload.update(ciphertext=ciphertext, iv=iv)
        enqueue(db, 'notification', payload)
        record(db, user, "user.invited", request, detail={"user_id": target.id, "role": target.role, "sign_in_method": body.sign_in_method})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Email is already registered")
    return {"user_id": target.id, "welcome_email_sent": False, "welcome_email_queued": True,
            "message": "User created; welcome email queued."}


@router.get('/notification-deliveries')
def welcome_deliveries(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = (db.query(BackgroundJob).filter_by(kind='notification', project_id=None)
            .order_by(BackgroundJob.created_at.desc()).limit(100).all())
    return [{'id': row.id, 'type': row.payload.get('type'), 'user_id': row.payload.get('user_id'), 'status': row.status,
             'outcome': (row.result or {}).get('outcome'), 'attempts': row.attempts,
             'max_attempts': row.max_attempts, 'last_error': row.last_error,
             'can_retry': can_retry_welcome(row),
             'created_at': row.created_at} for row in rows if row.payload.get('type') == 'welcome']


def can_retry_welcome(job: BackgroundJob) -> bool:
    created = job.created_at.replace(tzinfo=job.created_at.tzinfo or timezone.utc)
    return (job.status == 'failed' and created >= datetime.now(timezone.utc) - timedelta(hours=24)
            and (job.payload.get('method') == 'github' or 'ciphertext' in job.payload))


@router.post('/notification-deliveries/{job_id}/retry', status_code=202)
def retry_welcome_delivery(job_id: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    job = db.query(BackgroundJob).filter_by(id=job_id, kind='notification', project_id=None).with_for_update().first()
    if not job or job.payload.get('type') != 'welcome':
        raise HTTPException(404, 'Delivery not found')
    if not can_retry_welcome(job):
        raise HTTPException(409, 'This welcome email cannot be retried')
    job.status, job.attempts, job.last_error = 'queued', 0, None
    job.available_at = datetime.now(timezone.utc)
    record(db, user, 'notification.retry_requested', request, detail={'delivery_id':job.id})
    db.commit()
    return {'status':'queued'}


def find_target(db, actor, user_id):
    target = db.query(User).filter_by(id=user_id, organisation_id=actor.organisation_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == actor.id or target.role == "org_admin":
        raise HTTPException(403, "Cannot modify the organisation administrator")
    return target


@router.put("/users/{user_id}")
def update_user(user_id: str, body: UserUpdate, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = find_target(db, user, user_id)
    if body.role is not None and body.role != target.role:
        target.role = body.role
        record(db, user, "user.role_changed", request, detail={"user_id": target.id, "role": target.role})
    if body.is_active is not None and body.is_active != target.is_active:
        target.is_active = body.is_active
        record(db, user, "user.reactivated" if target.is_active else "user.deactivated", request, detail={"user_id": target.id})
    db.commit()
    return user_data(target)


@router.delete("/users/{user_id}")
def deactivate_user(user_id: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = find_target(db, user, user_id)
    if target.is_active:
        target.is_active = False
        record(db, user, "user.deactivated", request, detail={"user_id": target.id})
        db.commit()
    return {"message": "User deactivated"}
