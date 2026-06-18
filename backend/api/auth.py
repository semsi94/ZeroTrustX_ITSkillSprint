import base64
import hashlib
import io
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import (
    create_access_token,
    create_mfa_challenge_token,
    current_user,
    envelope,
    hash_password,
    verify_password,
)
from config import get_settings
from core.client_ip import get_client_ip
from core.crypto import decrypt, encrypt
from db.session import get_db

router = APIRouter(prefix="/auth", tags=["auth"])
api_router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: Optional[str] = None
    username_or_email: Optional[str] = None
    password: str


class MfaVerifyIn(BaseModel):
    challenge_token: str
    code: str = Field(..., min_length=6, max_length=8)
    remember_device: bool = False


class MfaConfirmIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class MfaDisableIn(BaseModel):
    password: str
    code: Optional[str] = Field(None, min_length=6, max_length=8)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=10, max_length=256)
    code: Optional[str] = Field(None, min_length=6, max_length=8)


def _login_error(message: str, reason: str, status_code: int = 401) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"message": message, "reason": reason},
    )


def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")[:1000]


def _hash(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _fingerprint(ip: str, ua_hash: str) -> str:
    return _hash(f"{ip}|{ua_hash}")


def _totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret, digits=6, interval=30)


def _safe_user(row) -> dict:
    return {
        "id": str(row["id"]),
        "username": row["username"],
        "email": row.get("email"),
        "display_name": row.get("display_name") or row["username"],
        "avatar_url": row.get("avatar_url"),
        "role": row["role"],
        "mfa_enabled": bool(row.get("mfa_enabled")),
    }


async def _record_attempt(
    db: AsyncSession,
    *,
    user_id=None,
    username: str,
    ip: str,
    direct_ip: Optional[str] = None,
    ip_resolution_source: str = "direct",
    user_agent: str,
    user_agent_hash: str,
    success: bool,
    risk_score: int = 0,
    risk_reasons: Optional[list[str]] = None,
    mfa_required: bool = False,
    mfa_success: Optional[bool] = None,
) -> None:
    stmt = text("""
        INSERT INTO login_attempts (
            user_id, username_or_email, ip_address, user_agent, user_agent_hash,
            direct_ip, resolved_client_ip, ip_resolution_source,
            success, risk_score, risk_reasons, mfa_required, mfa_success
        )
        VALUES (
            :user_id, :username, :ip, :ua, :ua_hash,
            :direct_ip, :resolved_client_ip, :ip_resolution_source,
            :success, :risk_score, :risk_reasons, :mfa_required, :mfa_success
        )
    """).bindparams(bindparam("risk_reasons", type_=JSONB))
    await db.execute(stmt, {
        "user_id": str(user_id) if user_id else None,
        "username": username,
        "ip": ip,
        "ua": user_agent,
        "ua_hash": user_agent_hash,
        "direct_ip": direct_ip or ip,
        "resolved_client_ip": ip,
        "ip_resolution_source": ip_resolution_source,
        "success": success,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons or [],
        "mfa_required": mfa_required,
        "mfa_success": mfa_success,
    })


async def _trusted_device_exists(db: AsyncSession, user_id, fp: str) -> bool:
    return bool((await db.execute(text("""
        SELECT id FROM trusted_devices
        WHERE user_id = :id AND device_fingerprint_hash = :fp
          AND revoked_at IS NULL AND expires_at > NOW()
        LIMIT 1
    """), {"id": str(user_id), "fp": fp})).scalar())


async def _trusted_device_mfa_fresh(db: AsyncSession, user_id, fp: str) -> bool:
    return bool((await db.execute(text("""
        SELECT id FROM trusted_devices
        WHERE user_id = :id AND device_fingerprint_hash = :fp
          AND revoked_at IS NULL
          AND expires_at > NOW()
          AND last_seen_at >= NOW() - INTERVAL '24 hours'
        LIMIT 1
    """), {"id": str(user_id), "fp": fp})).scalar())


async def _calculate_login_risk(db: AsyncSession, user, *, ip: str, ua_hash: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    trusted = await _trusted_device_exists(db, user["id"], _fingerprint(ip, ua_hash))
    if trusted:
        score -= 30
    if user.get("last_login_user_agent_hash") and user.get("last_login_user_agent_hash") != ua_hash:
        score += 30
        reasons.append("New device")
    if user.get("last_login_ip") and user.get("last_login_ip") != ip:
        score += 20
        reasons.append("New IP address")
    if int(user.get("failed_login_count") or 0) >= 3:
        score += 30
        reasons.append("Multiple failed login attempts")
    if user.get("last_login_at"):
        age = datetime.now(timezone.utc) - user["last_login_at"]
        if age > timedelta(days=30):
            score += 10
            reasons.append("Login after long inactivity")
    if user.get("role") == "admin":
        score += 10
        reasons.append("Admin account protection")
    if trusted:
        reasons.append("Known trusted device")
    if user.get("last_login_ip") == ip and user.get("last_login_user_agent_hash") == ua_hash:
        score -= 20
    return max(0, min(100, score)), reasons


async def _complete_login(db: AsyncSession, user, *, ip: str, ua_hash: str, mfa_at: Optional[datetime] = None) -> dict:
    await db.execute(text("""
        UPDATE users
        SET last_login_at = NOW(),
            last_login_ip = :ip,
            last_login_user_agent_hash = :ua_hash,
            failed_login_count = 0,
            locked_until = NULL
        WHERE id = :id
    """), {"id": str(user["id"]), "ip": ip, "ua_hash": ua_hash})
    token = create_access_token(user["username"], user["role"], user_id=str(user["id"]), mfa_at=mfa_at)
    return {"access_token": token, "user": _safe_user(user)}


@router.post("/login")
async def login(body: LoginIn, request: Request, db: AsyncSession = Depends(get_db)):
    username = (body.username_or_email or body.username or "").strip()
    client_ip = get_client_ip(request)
    ip = client_ip.ip
    user_agent = _ua(request)
    ua_hash = _hash(user_agent)
    if not username:
        raise _login_error("Enter your username/email and password", "missing_username", 400)
    if not body.password:
        raise _login_error("Enter your password", "missing_password", 400)

    row = (await db.execute(text("""
        SELECT * FROM users
        WHERE lower(username) = lower(:u) OR lower(email) = lower(:u)
        LIMIT 1
    """), {"u": username})).mappings().first()
    if not row:
        await _record_attempt(
            db, username=username, ip=ip, direct_ip=client_ip.direct_ip,
            ip_resolution_source=client_ip.source, user_agent=user_agent,
            user_agent_hash=ua_hash, success=False, risk_reasons=["Unknown account"],
        )
        await db.commit()
        raise _login_error("Invalid username/email or password", "invalid_credentials")

    if row.get("disabled") or row.get("is_active") is False:
        await _record_attempt(
            db, user_id=row["id"], username=username, ip=ip,
            direct_ip=client_ip.direct_ip, ip_resolution_source=client_ip.source,
            user_agent=user_agent, user_agent_hash=ua_hash, success=False,
            risk_reasons=["Disabled account"],
        )
        await db.commit()
        raise _login_error("Account is disabled", "account_disabled", 403)

    if not verify_password(body.password, row["password_hash"]):
        await db.execute(text("""
            UPDATE users
            SET failed_login_count = COALESCE(failed_login_count, 0) + 1,
                last_failed_login_at = NOW()
            WHERE id = :id
        """), {"id": str(row["id"])})
        await _record_attempt(
            db, user_id=row["id"] if row else None, username=username, ip=ip,
            direct_ip=client_ip.direct_ip, ip_resolution_source=client_ip.source,
            user_agent=user_agent, user_agent_hash=ua_hash, success=False,
        )
        await db.commit()
        raise _login_error("Invalid username/email or password", "invalid_credentials")

    if row.get("locked_until") and row["locked_until"] > datetime.now(timezone.utc):
        raise _login_error("Account is temporarily locked", "account_locked", 423)

    risk_score, risk_reasons = await _calculate_login_risk(db, row, ip=ip, ua_hash=ua_hash)
    device_fp = _fingerprint(ip, ua_hash)
    daily_mfa_fresh = await _trusted_device_mfa_fresh(db, row["id"], device_fp)
    daily_mfa_due = bool(get_settings().MFA_DAILY_REQUIRED and row.get("mfa_enabled")) and not daily_mfa_fresh
    if daily_mfa_due:
        risk_reasons.append("Daily MFA verification required")
    mfa_required = bool(row.get("mfa_enabled")) and (daily_mfa_due or risk_score >= 40)
    if mfa_required:
        await _record_attempt(
            db, user_id=row["id"], username=username, ip=ip, user_agent=user_agent,
            direct_ip=client_ip.direct_ip, ip_resolution_source=client_ip.source,
            user_agent_hash=ua_hash, success=True, risk_score=risk_score,
            risk_reasons=risk_reasons, mfa_required=True,
        )
        await db.commit()
        challenge_token = create_mfa_challenge_token(row["username"], row["role"], risk_score)
        await db.execute(text("""
            INSERT INTO mfa_challenges (username, token_hash, expires_at)
            VALUES (:username, :token_hash, NOW() + INTERVAL '5 minutes')
        """), {"username": row["username"], "token_hash": _hash(challenge_token)})
        await db.commit()
        return {
            "success": True,
            "mfa_required": True,
            "challenge_token": challenge_token,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
            "error": None,
        }

    data = await _complete_login(db, row, ip=ip, ua_hash=ua_hash)
    await _record_attempt(
        db, user_id=row["id"], username=username, ip=ip,
        direct_ip=client_ip.direct_ip, ip_resolution_source=client_ip.source,
        user_agent=user_agent, user_agent_hash=ua_hash, success=True,
        risk_score=risk_score, risk_reasons=risk_reasons,
    )
    await db.commit()
    return {"success": True, "mfa_required": False, **data, "error": None}


@api_router.post("/mfa/verify")
async def verify_mfa(body: MfaVerifyIn, request: Request, db: AsyncSession = Depends(get_db)):
    s = get_settings()
    try:
        payload = jwt.decode(body.challenge_token, s.JWT_SECRET_KEY, algorithms=[s.JWT_ALGORITHM])
    except JWTError:
        return {"success": False, "error": "Invalid or expired verification code"}
    if payload.get("typ") != "mfa_challenge":
        return {"success": False, "error": "Invalid or expired verification code"}
    challenge = (await db.execute(text("""
        SELECT id FROM mfa_challenges
        WHERE token_hash = :token_hash
          AND username = :username
          AND used_at IS NULL
          AND expires_at > NOW()
        LIMIT 1
    """), {"token_hash": _hash(body.challenge_token), "username": payload.get("sub")})).mappings().first()
    if not challenge:
        return {"success": False, "error": "Invalid or expired verification code"}
    row = (await db.execute(text("SELECT * FROM users WHERE username = :u"), {"u": payload.get("sub")})).mappings().first()
    if not row or not row.get("mfa_enabled") or not row.get("mfa_secret_encrypted"):
        return {"success": False, "error": "Invalid or expired verification code"}
    secret = decrypt(row["mfa_secret_encrypted"])
    ok = _totp(secret).verify(body.code, valid_window=1)
    client_ip = get_client_ip(request)
    ip = client_ip.ip
    user_agent = _ua(request)
    ua_hash = _hash(user_agent)
    await _record_attempt(
        db, user_id=row["id"], username=row["username"], ip=ip,
        direct_ip=client_ip.direct_ip, ip_resolution_source=client_ip.source,
        user_agent=user_agent, user_agent_hash=ua_hash, success=bool(ok),
        risk_score=int(payload.get("risk_score") or 0), mfa_required=True,
        mfa_success=bool(ok),
    )
    if not ok:
        await db.commit()
        return {"success": False, "error": "Invalid or expired verification code"}
    await db.execute(text("""
        UPDATE mfa_challenges SET used_at = NOW() WHERE id = :id
    """), {"id": str(challenge["id"])})
    await db.execute(text("UPDATE users SET last_mfa_at = NOW() WHERE id = :id"), {"id": str(row["id"])})
    trust_interval = "30 days" if body.remember_device else "1 day"
    await db.execute(text(f"""
        INSERT INTO trusted_devices (user_id, device_fingerprint_hash, ip_address, user_agent_hash, expires_at)
        VALUES (:id, :fp, :ip, :ua_hash, NOW() + INTERVAL '{trust_interval}')
        ON CONFLICT (user_id, device_fingerprint_hash)
        DO UPDATE SET
            ip_address = EXCLUDED.ip_address,
            user_agent_hash = EXCLUDED.user_agent_hash,
            last_seen_at = NOW(),
            expires_at = GREATEST(trusted_devices.expires_at, NOW() + INTERVAL '{trust_interval}'),
            revoked_at = NULL
    """), {"id": str(row["id"]), "fp": _fingerprint(ip, ua_hash), "ip": ip, "ua_hash": ua_hash})
    data = await _complete_login(db, row, ip=ip, ua_hash=ua_hash, mfa_at=datetime.now(timezone.utc))
    await db.commit()
    return {"success": True, **data, "error": None}


@router.get("/me")
async def me(user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return envelope(user)


@api_router.get("/mfa/status")
async def mfa_status(user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(text("""
        SELECT mfa_enabled, mfa_enrolled_at, last_mfa_at
        FROM users WHERE id = :id
    """), {"id": user["id"]})).mappings().first()
    return {
        "success": True,
        "managed_by": "local_totp",
        "mfa_enabled": bool(row and row.get("mfa_enabled")),
        "mfa_enrolled_at": row["mfa_enrolled_at"].isoformat() if row and row.get("mfa_enrolled_at") else None,
        "last_mfa_at": row["last_mfa_at"].isoformat() if row and row.get("last_mfa_at") else None,
        "daily_required": get_settings().MFA_DAILY_REQUIRED,
        "error": None,
    }


@api_router.post("/mfa/setup/start")
async def mfa_setup_start(user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    secret = pyotp.random_base32()
    await db.execute(text("""
        UPDATE users SET mfa_pending_secret_encrypted = :secret WHERE id = :id
    """), {"id": user["id"], "secret": encrypt(secret)})
    await db.commit()
    issuer = "ZeroTrustX"
    otpauth = pyotp.totp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=issuer)
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    return {"success": True, "otpauth_url": otpauth, "qr_code_data_url": qr, "manual_key": secret, "error": None}


@api_router.post("/mfa/setup/confirm")
async def mfa_setup_confirm(body: MfaConfirmIn, user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(text("SELECT mfa_pending_secret_encrypted FROM users WHERE id = :id"), {"id": user["id"]})).mappings().first()
    secret = decrypt(row["mfa_pending_secret_encrypted"]) if row and row.get("mfa_pending_secret_encrypted") else ""
    if not secret or not _totp(secret).verify(body.code, valid_window=1):
        return {"success": False, "error": "Invalid or expired verification code"}
    await db.execute(text("""
        UPDATE users
        SET mfa_enabled = TRUE,
            mfa_secret_encrypted = :secret,
            mfa_pending_secret_encrypted = NULL,
            mfa_enrolled_at = NOW(),
            last_mfa_at = NOW()
        WHERE id = :id
    """), {"id": user["id"], "secret": encrypt(secret)})
    await db.commit()
    return {"success": True, "mfa_enabled": True, "error": None}


@api_router.post("/mfa/disable")
async def mfa_disable(body: MfaDisableIn, user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user["id"]})).mappings().first()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=403, detail="Password confirmation failed")
    if row.get("mfa_enabled"):
        secret = decrypt(row.get("mfa_secret_encrypted") or "")
        if not body.code or not _totp(secret).verify(body.code, valid_window=1):
            return {"success": False, "error": "Invalid or expired verification code"}
    await db.execute(text("""
        UPDATE users
        SET mfa_enabled = FALSE,
            mfa_secret_encrypted = NULL,
            mfa_pending_secret_encrypted = NULL,
            mfa_enrolled_at = NULL
        WHERE id = :id
    """), {"id": user["id"]})
    await db.commit()
    return {"success": True, "mfa_enabled": False, "error": None}


@api_router.post("/mfa/step-up/verify")
async def mfa_step_up(body: MfaConfirmIn, user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user["id"]})).mappings().first()
    if not row or not row.get("mfa_enabled"):
        return {"success": True, "access_token": create_access_token(user["username"], user["role"], user_id=user["id"]), "error": None}
    secret = decrypt(row.get("mfa_secret_encrypted") or "")
    if not secret or not _totp(secret).verify(body.code, valid_window=1):
        return {"success": False, "error": "Invalid or expired verification code"}
    await db.execute(text("UPDATE users SET last_mfa_at = NOW() WHERE id = :id"), {"id": user["id"]})
    await db.commit()
    token = create_access_token(row["username"], row["role"], user_id=str(row["id"]), mfa_at=datetime.now(timezone.utc))
    return {"success": True, "access_token": token, "user": _safe_user(row), "error": None}


@api_router.post("/password/change")
async def change_password(body: PasswordChangeIn, user: dict = Depends(current_user), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user["id"]})).mappings().first()
    if not row or not verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    if row.get("mfa_enabled"):
        secret = decrypt(row.get("mfa_secret_encrypted") or "")
        if not body.code or not secret or not _totp(secret).verify(body.code, valid_window=1):
            return {"success": False, "error": "Invalid or expired verification code"}
    await db.execute(text("""
        UPDATE users
        SET password_hash = :hash,
            updated_at = NOW()
        WHERE id = :id
    """), {"id": user["id"], "hash": hash_password(body.new_password)})
    await db.commit()
    return {"success": True, "error": None}
