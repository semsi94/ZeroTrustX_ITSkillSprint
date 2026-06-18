from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user, require_recent_mfa
from config import get_settings
from db.session import get_db
from services.demo_mode import demo_banner_meta, demo_catalog
from services.demo_seed_service import reset_demo_data, seed_demo_data

router = APIRouter(prefix="/api/demo", tags=["demo"])


def _require_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")


@router.get("/status")
async def demo_status(user: dict = Depends(current_user)):
    settings = get_settings()
    summary = demo_catalog()["meta"]["status_summary"]
    return {
        "success": True,
        **demo_banner_meta(),
        "enabled": bool(settings.DEMO_MODE),
        "seed_on_start": bool(settings.DEMO_SEED_ON_START),
        "reset_on_start": bool(settings.DEMO_RESET_ON_START),
        "summary": summary,
        "error": None,
    }


@router.post("/seed")
async def demo_seed(
    reset_first: bool = True,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_recent_mfa),
):
    _require_admin(user)
    return await seed_demo_data(db, reset_first=reset_first)


@router.post("/reset")
async def demo_reset(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_recent_mfa),
):
    _require_admin(user)
    return await reset_demo_data(db)
