from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from db.session import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(subject: str, role: str, *, user_id: Optional[str] = None, mfa_at: Optional[datetime] = None) -> str:
    s = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=s.JWT_EXPIRE_MINUTES)
    payload = {"sub": subject, "role": role, "exp": expire, "typ": "access"}
    if user_id:
        payload["uid"] = user_id
    if mfa_at:
        payload["mfa_at"] = int(mfa_at.timestamp())
    return jwt.encode(payload, s.JWT_SECRET_KEY, algorithm=s.JWT_ALGORITHM)


def create_mfa_challenge_token(subject: str, role: str, risk_score: int) -> str:
    s = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {"sub": subject, "role": role, "risk_score": risk_score, "exp": expire, "typ": "mfa_challenge"}
    return jwt.encode(payload, s.JWT_SECRET_KEY, algorithm=s.JWT_ALGORITHM)


async def current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = _decode_access_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    row = (await db.execute(text("""
        SELECT * FROM users
        WHERE lower(username) = lower(:username)
        LIMIT 1
    """), {"username": username})).mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if row.get("disabled") or row.get("is_active") is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")
    return _user_from_row(row, payload)


async def current_user_token(token: Optional[str] = Depends(oauth2_scheme)) -> dict:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = _decode_access_token(token)
    return {
        "id": payload.get("uid"),
        "username": payload.get("sub"),
        "role": payload.get("role") or "viewer",
        "mfa_at": payload.get("mfa_at"),
    }


def _decode_access_token(token: str) -> dict:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.JWT_SECRET_KEY, algorithms=[s.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if payload.get("typ") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload


def _user_from_row(row, payload: Optional[dict] = None) -> dict:
    payload = payload or {}
    return {
        "id": str(row["id"]),
        "username": row["username"],
        "email": row.get("email"),
        "display_name": row.get("display_name") or row["username"],
        "avatar_url": row.get("avatar_url"),
        "role": row["role"],
        "mfa_enabled": bool(row.get("mfa_enabled")),
        "mfa_at": payload.get("mfa_at"),
    }


def require_role(*roles: str):
    async def checker(user: dict = Depends(current_user)):
        if user["role"] == "admin":
            return user
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return checker


async def require_recent_mfa(
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    row = (
        await db.execute(
            text("SELECT mfa_enabled FROM users WHERE id = :id OR username = :u"),
            {"id": user.get("id"), "u": user["username"]},
        )
    ).mappings().first()
    mfa_age = user.get("mfa_at")
    if row and row.get("mfa_enabled") and mfa_age is None:
        raise HTTPException(status_code=403, detail="Recent MFA verification required")
    if row and row.get("mfa_enabled") and mfa_age is not None and int(datetime.now(timezone.utc).timestamp()) - int(mfa_age) > 900:
        raise HTTPException(status_code=403, detail="Recent MFA verification required")
    return user


def envelope(data=None, success: bool = True, error: Optional[str] = None) -> dict:
    return {"success": success, "data": data, "error": error}
