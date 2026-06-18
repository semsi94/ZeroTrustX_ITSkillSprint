from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user
from api.incidents import _insert_evidence, _require_write
from db.session import get_db


router = APIRouter(prefix="/api/evidence", tags=["evidence"])


class EvidencePromoteIn(BaseModel):
    incident_id: UUID
    event: Optional[dict] = None
    events: list[dict] = Field(default_factory=list, max_length=500)


@router.post("/promote")
async def promote_evidence(
    body: EvidencePromoteIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    events = list(body.events or [])
    if body.event:
        events.insert(0, body.event)
    if not events:
        raise HTTPException(status_code=400, detail="No evidence events provided")
    exists = (await db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": str(body.incident_id)})).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    added = await _insert_evidence(db, str(body.incident_id), events, user)
    await db.commit()
    return {
        "success": True,
        "incidentId": str(body.incident_id),
        "added": added,
        "candidateCount": len(events),
        "error": None,
    }
