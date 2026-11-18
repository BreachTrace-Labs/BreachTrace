"""Initial organisation registration and session endpoints."""
from datetime import datetime, timezone
import os
from urllib.parse import urlsplit

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import create_access_token, ensure_single_organisation, get_active_user, get_current_user, hash_password, verify_password
from db.database import get_db
from db.models import Organisation, User
from audit import record
from rate_limit import limiter
from github_oauth import GitHubOAuthError, fetch_identity

router = APIRouter(prefix="/auth", tags=["auth"])


class Registration(BaseModel):
    org_name: str = Field(min_length=1, max_length=120)
    slug: str = Field(min_length=1, max_length=60, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    admin_email: EmailStr
    admin_password: str = Field(min_length=10, max_length=72)
    admin_full_name: str = Field(min_length=1, max_length=120)


class GitHubExchange(BaseModel):
    code: str = Field(min_length=1, max_length=2048)
    code_verifier: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$")


def github_oauth_config():
    client_id = os.environ.get("GITHUB_OAUTH_CLIENT_ID", "").strip()
    secret = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "").strip()
    callback = os.environ.get("GITHUB_OAUTH_CALLBACK_URL", "").strip()
    try:
        parsed = urlsplit(callback)
        safe_scheme = parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"))
        valid = safe_scheme and parsed.hostname and not parsed.username and not parsed.password and parsed.path == "/auth/github/callback" and not parsed.query and not parsed.fragment and (parsed.port is None or 1 <= parsed.port <= 65535)
    except ValueError:
        valid = False
    return (client_id, secret, callback) if client_id and secret and valid else None


class ProfileUpdate(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=72)


def profile(user: User) -> dict:
    return {"id": user.id, "email": user.email, "full_name": user.full_name,
            "role": user.role, "organisation_id": user.organisation_id,
            "must_change_password": user.must_change_password, "has_password": user.hashed_password is not None}


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
    try:
        db.flush()
        user = User(organisation_id=org.id, email=body.admin_email.lower(), full_name=body.admin_full_name.strip(),
                    role="org_admin", hashed_password=password)
        db.add(user)
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
    ensure_single_organisation(db)
    access_token = create_access_token(user.id)
    user.last_login_at = datetime.now(timezone.utc)
    record(db, user, "auth.login", request)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer", "user": profile(user)}


@router.get("/github/config")
def github_config():
    config = github_oauth_config()
    return {"enabled": bool(config), "client_id": config[0] if config else None,
            "callback_url": config[2] if config else None}


@router.post("/github/exchange")
@limiter.limit("10/minute")
async def github_exchange(body: GitHubExchange, request: Request, db: Session = Depends(get_db)):
    config = github_oauth_config()
    if config is None:
        raise HTTPException(503, "GitHub sign-in is not configured")
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            identity = await fetch_identity(client, client_id=config[0], client_secret=config[1],
                                            code=body.code, redirect_uri=config[2], code_verifier=body.code_verifier)
    except GitHubOAuthError:
        raise HTTPException(401, "Could not verify GitHub sign-in. Please try again.") from None
    ensure_single_organisation(db)
    if not identity.verified_emails:
        raise HTTPException(403, "No invited account matches a verified GitHub email.")
    users = db.query(User).filter(func.lower(User.email).in_(identity.verified_emails), User.is_active.is_(True)).limit(2).all()
    if len(users) != 1:
        raise HTTPException(403, "No unique invited account matches a verified GitHub email. Contact your administrator.")
    user = users[0]
    user.last_login_at = datetime.now(timezone.utc)
    record(db, user, "auth.github_login", request)
    db.commit()
    return {"access_token": create_access_token(user.id), "token_type": "bearer", "user": profile(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return profile(user)


@router.put("/me")
def update_profile(body: ProfileUpdate, request: Request, user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    name = body.full_name.strip()
    if not name:
        raise HTTPException(422, "Full name cannot be empty")
    user.full_name = name
    record(db, user, "user.profile_updated", request)
    db.commit()
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
