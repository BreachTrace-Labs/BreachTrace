"""Organisation and team administration."""
from typing import Literal
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import get_active_user, hash_password, require_admin
from audit import public as audit_public, record
from db.database import get_db
from db.models import AuditLog, Organisation, User

router = APIRouter(prefix="/org", tags=["organisation"])


class OrgUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class Invite(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    role: Literal["security_lead", "developer"]
    temporary_password: str = Field(min_length=10, max_length=72)


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
    try:
        password = hash_password(body.temporary_password)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    target = User(organisation_id=user.organisation_id, email=body.email.lower(), full_name=name,
                  role=body.role, hashed_password=password, must_change_password=True)
    db.add(target)
    try:
        db.flush()
        record(db, user, "user.invited", request, detail={"user_id": target.id, "role": target.role})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Email is already registered")
    return {"user_id": target.id, "message": "User created; share the temporary password securely"}


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
