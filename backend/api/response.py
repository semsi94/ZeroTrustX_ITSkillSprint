from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from api.deps import current_user, envelope
from db.session import get_db

router = APIRouter(prefix="/response", tags=["response"])


def _row(r) -> dict:
    return {
        "id": str(r["id"]),
        "incident_id": str(r["incident_id"]) if r["incident_id"] else None,
        "incident_title": r.get("incident_title"),
        "incident_severity": r.get("incident_severity"),
        "action_type": r["action_type"],
        "target": r["target"],
        "alias": r["alias"],
        "status": r["status"],
        "initiated_by": r["initiated_by"],
        "approved_by": r["approved_by"],
        "initiated_at": r["initiated_at"].isoformat() if r["initiated_at"] else None,
        "executed_at": r["executed_at"].isoformat() if r["executed_at"] else None,
        "reverted_at": r["reverted_at"].isoformat() if r["reverted_at"] else None,
        "output": r["output"],
        "error_message": r["error_message"],
        "rollback_available": r["rollback_available"],
    }


BASE_SELECT = """
SELECT ra.*, i.title AS incident_title, i.severity AS incident_severity
FROM response_actions ra
LEFT JOIN incidents i ON i.id = ra.incident_id
"""


@router.get("/pending")
async def pending(
    db: AsyncSession = Depends(get_db), user: dict = Depends(current_user),
):
    rows = (await db.execute(text(
        BASE_SELECT + "WHERE ra.status IN ('pending','pending_approval') "
        "ORDER BY ra.initiated_at DESC LIMIT 200"
    ))).mappings().all()
    return envelope([_row(r) for r in rows])


@router.get("/executed")
async def executed(
    db: AsyncSession = Depends(get_db), user: dict = Depends(current_user),
):
    rows = (await db.execute(text(
        BASE_SELECT + "WHERE ra.status = 'executed' "
        "ORDER BY ra.executed_at DESC NULLS LAST LIMIT 50"
    ))).mappings().all()
    return envelope([_row(r) for r in rows])


@router.get("/failed")
async def failed(
    db: AsyncSession = Depends(get_db), user: dict = Depends(current_user),
):
    rows = (await db.execute(text(
        BASE_SELECT + "WHERE ra.status = 'failed' "
        "ORDER BY ra.initiated_at DESC LIMIT 100"
    ))).mappings().all()
    return envelope([_row(r) for r in rows])


class DecisionIn(BaseModel):
    decision: str  # "approve" | "reject"


@router.post("/{action_id}/decision")
async def decision(
    action_id: UUID,
    body: DecisionIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    if user["role"] not in ("admin", "senior_analyst"):
        raise HTTPException(status_code=403, detail="Senior role required")

    row = (await db.execute(text("""
        SELECT id, target, alias, status FROM response_actions WHERE id = :id
    """), {"id": str(action_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    if row["status"] != "pending_approval":
        raise HTTPException(status_code=409, detail="Action not awaiting approval")

    if body.decision == "reject":
        await db.execute(text("""
            UPDATE response_actions SET status = 'rejected', approved_by = :u WHERE id = :id
        """), {"u": user["username"], "id": str(action_id)})
        await db.commit()
        return envelope({"id": str(action_id), "status": "rejected"})

    if body.decision != "approve":
        raise HTTPException(status_code=400, detail="decision must be approve or reject")

    await db.execute(text("""
        UPDATE response_actions SET status = 'pending', approved_by = :u WHERE id = :id
    """), {"u": user["username"], "id": str(action_id)})
    await db.commit()

    from workers.response_tasks import block_ip_task
    task = block_ip_task.delay(row["target"], None, str(action_id), row["alias"])
    return envelope({"id": str(action_id), "status": "approved", "task_id": task.id})


@router.post("/{action_id}/retry")
async def retry(
    action_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    row = (await db.execute(text("""
        SELECT id, target, alias, action_type, status FROM response_actions WHERE id = :id
    """), {"id": str(action_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    if row["status"] != "failed":
        raise HTTPException(status_code=409, detail="Action is not failed")

    await db.execute(text("""
        UPDATE response_actions SET status = 'pending', error_message = NULL WHERE id = :id
    """), {"id": str(action_id)})
    await db.commit()

    from workers.response_tasks import block_ip_task, unblock_ip_task
    if row["action_type"] == "block_ip":
        task = block_ip_task.delay(row["target"], None, str(action_id), row["alias"])
    else:
        task = unblock_ip_task.delay(row["target"], str(action_id), row["alias"])
    return envelope({"task_id": task.id})
