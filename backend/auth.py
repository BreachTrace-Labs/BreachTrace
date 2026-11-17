"""Password and JWT authentication for the organisation foundation."""
import os
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def _secret() -> str:
    value = os.environ.get("JWT_SECRET_KEY", "")
    if len(value) < 32:
        raise RuntimeError("JWT_SECRET_KEY must contain at least 32 characters")
    return value


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed or len(password.encode("utf-8")) > 72:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


def create_access_token(user_id: str) -> str:
    minutes = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "iat": now, "exp": now + timedelta(minutes=minutes)}, _secret(), algorithm="HS256")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        user_id = payload.get("sub")
        if not isinstance(user_id, str):
            raise ValueError("Missing subject")
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_role(*roles: str):
    def check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return check


require_admin = require_role("org_admin")
require_admin_or_lead = require_role("org_admin", "security_lead")
require_any_role = require_role("org_admin", "security_lead", "developer")
