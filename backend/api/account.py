import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user
from db.session import get_db

router = APIRouter(prefix="/api/account", tags=["account"])


class ProfileIn(BaseModel):
    username: str | None = Field(None, min_length=3, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    display_name: str | None = Field(None, max_length=255)


class PreferencesIn(BaseModel):
    email_notifications_enabled: bool | None = None
    incident_notifications_enabled: bool | None = None
    alert_notifications_enabled: bool | None = None
    weekly_report_enabled: bool | None = None
    theme: str | None = Field(None, pattern="^(system|dark|light)$")
    table_density: str | None = Field(None, pattern="^(compact|comfortable|spacious)$")
    default_time_range: str | None = Field(None, max_length=40)
    default_page_size: int | None = Field(None, ge=25, le=500)


def _profile(row) -> dict:
    return {
        "id": str(row["id"]),
        "username": row.get("username"),
        "email": row.get("email"),
        "display_name": row.get("display_name"),
        "avatar_url": row.get("avatar_url"),
        "role": row.get("role"),
        "is_active": bool(row.get("is_active", not row.get("disabled", False))),
        "mfa_enabled": bool(row.get("mfa_enabled")),
        "mfa_enrolled_at": row["mfa_enrolled_at"].isoformat() if row.get("mfa_enrolled_at") else None,
        "last_mfa_at": row["last_mfa_at"].isoformat() if row.get("last_mfa_at") else None,
        "last_login_at": row["last_login_at"].isoformat() if row.get("last_login_at") else None,
        "last_login_ip": row.get("last_login_ip"),
        "last_login_country": row.get("last_login_country"),
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
    }


def _preferences(row) -> dict:
    data = dict(row)
    data["user_id"] = str(data["user_id"])
    data["updated_at"] = data["updated_at"].isoformat() if data.get("updated_at") else None
    return data


async def _user_row(db: AsyncSession, user: dict):
    row = (await db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user["id"]})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Account profile not found")
    return row


@router.get("/profile")
async def get_profile(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    return {"success": True, "profile": _profile(await _user_row(db, user)), "error": None}


@router.get("/me")
async def get_me(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    profile = _profile(await _user_row(db, user))
    return {"success": True, "profile": profile, "user": profile, "error": None}


@router.patch("/profile")
async def update_profile(body: ProfileIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    current = await _user_row(db, user)
    username = body.username.strip() if body.username else current["username"]
    if username != current["username"]:
        exists = (await db.execute(text("""
            SELECT 1 FROM users WHERE lower(username) = lower(:u) AND id <> :id LIMIT 1
        """), {"u": username, "id": user["id"]})).scalar()
        if exists:
            raise HTTPException(status_code=400, detail="Username is already taken")
    await db.execute(text("""
        UPDATE users
        SET username = :username,
            display_name = COALESCE(:display_name, display_name),
            updated_at = NOW()
        WHERE id = :id
    """), {
        "id": user["id"],
        "username": username,
        "display_name": body.display_name,
    })
    await db.commit()
    return {"success": True, "profile": _profile(await _user_row(db, user)), "error": None}


@router.post("/avatar")
async def upload_avatar(file: UploadFile = File(...), db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    allowed = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp"}
    if file.content_type not in allowed:
        raise HTTPException(status_code=400, detail="Avatar must be PNG, JPG, or WebP")
    data = await file.read()
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Avatar must be 2 MB or smaller")
    path = Path(__file__).resolve().parents[1] / "uploads" / "avatars"
    path.mkdir(parents=True, exist_ok=True)
    name = f"{user['id']}-{uuid.uuid4().hex}{allowed[file.content_type]}"
    target = path / name
    target.write_bytes(data)
    avatar_url = f"/uploads/avatars/{name}"
    await db.execute(text("UPDATE users SET avatar_url = :url, updated_at = NOW() WHERE id = :id"), {"url": avatar_url, "id": user["id"]})
    await db.commit()
    return {"success": True, "avatar_url": avatar_url, "profile": _profile(await _user_row(db, user)), "error": None}


@router.get("/preferences")
async def get_preferences(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    await db.execute(text("INSERT INTO user_preferences (user_id) VALUES (:id) ON CONFLICT (user_id) DO NOTHING"), {"id": user["id"]})
    await db.commit()
    row = (await db.execute(text("SELECT * FROM user_preferences WHERE user_id = :id"), {"id": user["id"]})).mappings().first()
    return {"success": True, "preferences": _preferences(row), "error": None}


@router.patch("/preferences")
async def update_preferences(body: PreferencesIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    values = body.model_dump(exclude_unset=True)
    await db.execute(text("INSERT INTO user_preferences (user_id) VALUES (:id) ON CONFLICT (user_id) DO NOTHING"), {"id": user["id"]})
    if values:
        assignments = ", ".join(f"{key} = :{key}" for key in values)
        await db.execute(text(f"UPDATE user_preferences SET {assignments}, updated_at = NOW() WHERE user_id = :id"), {"id": user["id"], **values})
    await db.commit()
    row = (await db.execute(text("SELECT * FROM user_preferences WHERE user_id = :id"), {"id": user["id"]})).mappings().first()
    return {"success": True, "preferences": _preferences(row), "error": None}
