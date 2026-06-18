import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from core.pipeline import ingest_event
from db.session import get_db

log = logging.getLogger("zerotrustx.webhook")
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/splunk")
async def splunk_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    try:
        result = await ingest_event(payload, db)
    except Exception as e:
        log.exception("Webhook ingest_event raised")
        raise HTTPException(status_code=500, detail=str(e))

    if not result.get("success"):
        raise HTTPException(status_code=422, detail={
            "success": False,
            "error": result.get("error"),
            "step": result.get("step"),
        })

    return {
        "success": True,
        "incident_id": result["incident_id"],
        "response_level": result["response_level"],
        "mode": result.get("mode"),
    }
