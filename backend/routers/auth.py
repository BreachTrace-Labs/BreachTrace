"""Initial organisation registration and session endpoints."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import create_access_token, get_current_user, hash_password, verify_password
from db.database import get_db
from db.models import Organisation, User
from audit import record
from rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


class Registration(BaseModel):
    org_name: str = Field(min_length=1, max_length=120)
    slug: str = Field(min_length=1, max_length=60, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    admin_email: EmailStr
    admin_password: str = Field(min_length=10, max_length=72)
    admin_full_name: str = Field(min_length=1, max_length=120)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=72)


def profile(user: User) -> dict:
    return {"id": user.id, "email": user.email, "full_name": user.full_name,
            "role": user.role, "organisation_id": user.organisation_id,
            "must_change_password": user.must_change_password}


@router.get("/setup-status")
def setup_status(db: Session = Depends(get_db)):
    return {"setup_required": db.query(Organisation.id).first() is None}


@router.post("/register", status_code=201)
def register(body: Registration, db: Session = Depends(get_db)):
    # The transaction lock makes concurrent first registrations mutually exclusive.
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(918270381)"))
    if db.query(Organisation.id).first() is not None:
        raise HTTPException(status_code=409, detail="Organisation already configured")
    try:
        password = hash_password(body.admin_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    org = Organisation(name=body.org_name.strip(), slug=body.slug)
    db.add(org)
    db.flush()
    user = User(organisation_id=org.id, email=body.admin_email.lower(), full_name=body.admin_full_name.strip(),
                role="org_admin", hashed_password=password)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Organisation or email already exists")
    return {"message": "Organisation created", "user_id": user.id}


@router.post("/token")
@limiter.limit("5/minute")
def token(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username.strip().lower()).first()
    if not user or not user.is_active or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(user.id)
    user.last_login_at = datetime.now(timezone.utc)
    record(db, user, "auth.login", request)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer", "user": profile(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return profile(user)


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record(db, user, "auth.logout", request)
    db.commit()
    return {"message": "Logged out"}


@router.post("/change-password")
def change_password(body: PasswordChange, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    try:
        user.hashed_password = hash_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    user.must_change_password = False
    record(db, user, "auth.password_changed", request)
    db.commit()
    return {"message": "Password changed"}
