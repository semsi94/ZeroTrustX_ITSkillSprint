import uuid
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user
from db.session import get_db


router = APIRouter(prefix="/api/tickets", tags=["tickets"])
incident_router = APIRouter(prefix="/api/incidents", tags=["tickets"])

TICKET_STATUSES = {
    "open",
    "assigned",
    "in_progress",
    "waiting",
    "escalated",
    "resolved",
    "closed",
    "cancelled",
}
TICKET_PRIORITIES = {"critical", "high", "medium", "low"}


def _require_ticket_write(user: dict) -> None:
    if user.get("role") in {"viewer", "degraded"}:
        raise HTTPException(status_code=403, detail="Viewer role is read-only")


def _require_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


def _normalize_status(value: Optional[str], default: str = "open") -> str:
    status = str(value or default).strip().lower().replace(" ", "_").replace("-", "_")
    if status not in TICKET_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid ticket status")
    return status


def _normalize_priority(value: Optional[str], default: str = "medium") -> str:
    priority = str(value or default).strip().lower().replace(" ", "_").replace("-", "_")
    if priority not in TICKET_PRIORITIES:
        raise HTTPException(status_code=400, detail="Invalid ticket priority")
    return priority


def _parse_sla(value: Optional[str]):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid SLA due date")


def _ticket_number() -> str:
    return f"SOC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def _ticket_row(row) -> dict:
    return {
        "id": str(row["id"]),
        "ticket_number": row.get("ticket_number"),
        "incident_id": str(row["incident_id"]) if row.get("incident_id") else None,
        "incident_title": row.get("incident_title"),
        "title": row.get("title"),
        "description": row.get("description") or "",
        "queue": row.get("queue") or "",
        "assignee": row.get("assignee") or "",
        "priority": row.get("priority") or "medium",
        "status": row.get("status") or "open",
        "sla_due_at": row["sla_due_at"].isoformat() if row.get("sla_due_at") else None,
        "escalation_level": int(row.get("escalation_level") or 0),
        "requested_action": row.get("requested_action") or "",
        "resolution_notes": row.get("resolution_notes") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        "closed_at": row["closed_at"].isoformat() if row.get("closed_at") else None,
    }


class TicketCreateIn(BaseModel):
    incident_id: Optional[UUID] = None
    title: str = Field(..., min_length=3, max_length=300)
    description: Optional[str] = Field("", max_length=5000)
    queue: Optional[str] = Field("SOC", max_length=120)
    assignee: Optional[str] = Field("", max_length=255)
    priority: str = "medium"
    status: str = "open"
    sla_due_at: Optional[str] = None
    escalation_level: int = Field(0, ge=0, le=5)
    requested_action: Optional[str] = Field("", max_length=3000)
    resolution_notes: Optional[str] = Field("", max_length=5000)


class TicketPatchIn(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=300)
    description: Optional[str] = Field(None, max_length=5000)
    queue: Optional[str] = Field(None, max_length=120)
    assignee: Optional[str] = Field(None, max_length=255)
    priority: Optional[str] = None
    status: Optional[str] = None
    sla_due_at: Optional[str] = None
    escalation_level: Optional[int] = Field(None, ge=0, le=5)
    requested_action: Optional[str] = Field(None, max_length=3000)
    resolution_notes: Optional[str] = Field(None, max_length=5000)


async def _incident_exists(db: AsyncSession, incident_id: Optional[UUID]) -> None:
    if not incident_id:
        return
    exists = (await db.execute(
        text("SELECT id FROM incidents WHERE id = :id"),
        {"id": str(incident_id)},
    )).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")


async def _create_ticket(db: AsyncSession, body: TicketCreateIn, user: dict, incident_id: Optional[UUID] = None) -> dict:
    incident_id = incident_id or body.incident_id
    await _incident_exists(db, incident_id)
    status = _normalize_status(body.status)
    priority = _normalize_priority(body.priority)
    closed_at = datetime.now(timezone.utc) if status in {"closed", "cancelled"} else None
    row = (await db.execute(text("""
        INSERT INTO tickets (
            ticket_number, incident_id, title, description, queue, assignee,
            priority, status, sla_due_at, escalation_level, requested_action,
            resolution_notes, created_by, closed_at, updated_at
        )
        VALUES (
            :ticket_number, :incident_id, :title, :description, :queue, :assignee,
            :priority, :status, :sla_due_at, :escalation_level, :requested_action,
            :resolution_notes, :created_by, :closed_at, NOW()
        )
        RETURNING *
    """), {
        "ticket_number": _ticket_number(),
        "incident_id": str(incident_id) if incident_id else None,
        "title": body.title.strip(),
        "description": body.description or "",
        "queue": body.queue or "SOC",
        "assignee": body.assignee or "",
        "priority": priority,
        "status": status,
        "sla_due_at": _parse_sla(body.sla_due_at),
        "escalation_level": body.escalation_level,
        "requested_action": body.requested_action or "",
        "resolution_notes": body.resolution_notes or "",
        "created_by": user.get("username"),
        "closed_at": closed_at,
    })).mappings().first()
    await db.commit()
    return _ticket_row(row)


@router.get("")
async def list_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assignee: Optional[str] = None,
    queue: Optional[str] = None,
    incident_id: Optional[UUID] = None,
    search: Optional[str] = None,
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    clauses = []
    params: dict = {"limit": limit}
    if status:
        clauses.append("t.status = :status")
        params["status"] = _normalize_status(status)
    if priority:
        clauses.append("t.priority = :priority")
        params["priority"] = _normalize_priority(priority)
    if assignee:
        clauses.append("t.assignee ILIKE :assignee")
        params["assignee"] = f"%{assignee}%"
    if queue:
        clauses.append("t.queue ILIKE :queue")
        params["queue"] = f"%{queue}%"
    if incident_id:
        clauses.append("t.incident_id = :incident_id")
        params["incident_id"] = str(incident_id)
    if search:
        clauses.append("(t.title ILIKE :search OR t.description ILIKE :search OR t.ticket_number ILIKE :search OR t.requested_action ILIKE :search)")
        params["search"] = f"%{search}%"
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    rows = (await db.execute(text(f"""
        SELECT t.*, i.title AS incident_title
        FROM tickets t
        LEFT JOIN incidents i ON i.id = t.incident_id
        {where}
        ORDER BY
            CASE WHEN t.status IN ('open','assigned','in_progress','waiting','escalated') THEN 0 ELSE 1 END,
            t.sla_due_at ASC NULLS LAST,
            t.updated_at DESC
        LIMIT :limit
    """), params)).mappings().all()
    return {"success": True, "tickets": [_ticket_row(row) for row in rows], "count": len(rows), "error": None}


@router.post("")
async def create_ticket(
    body: TicketCreateIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_ticket_write(user)
    ticket = await _create_ticket(db, body, user)
    return {"success": True, "ticket": ticket, "error": None}


@router.get("/{ticket_id}")
async def get_ticket(
    ticket_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    row = (await db.execute(text("""
        SELECT t.*, i.title AS incident_title
        FROM tickets t
        LEFT JOIN incidents i ON i.id = t.incident_id
        WHERE t.id = :id
    """), {"id": str(ticket_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return {"success": True, "ticket": _ticket_row(row), "error": None}


@router.patch("/{ticket_id}")
async def update_ticket(
    ticket_id: UUID,
    body: TicketPatchIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_ticket_write(user)
    updates = ["updated_at = NOW()"]
    params: dict = {"id": str(ticket_id)}
    for field in ("title", "description", "queue", "assignee", "requested_action", "resolution_notes"):
        value = getattr(body, field)
        if value is not None:
            updates.append(f"{field} = :{field}")
            params[field] = value.strip() if isinstance(value, str) else value
    if body.priority is not None:
        updates.append("priority = :priority")
        params["priority"] = _normalize_priority(body.priority)
    if body.status is not None:
        status = _normalize_status(body.status)
        updates.append("status = :status")
        params["status"] = status
        if status in {"closed", "cancelled"}:
            updates.append("closed_at = COALESCE(closed_at, NOW())")
        else:
            updates.append("closed_at = NULL")
    if body.sla_due_at is not None:
        updates.append("sla_due_at = :sla_due_at")
        params["sla_due_at"] = _parse_sla(body.sla_due_at)
    if body.escalation_level is not None:
        updates.append("escalation_level = :escalation_level")
        params["escalation_level"] = body.escalation_level

    row = (await db.execute(text(f"""
        UPDATE tickets
        SET {', '.join(updates)}
        WHERE id = :id
        RETURNING *
    """), params)).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Ticket not found")
    await db.commit()
    return {"success": True, "ticket": _ticket_row(row), "error": None}


@router.delete("/{ticket_id}")
async def delete_ticket(
    ticket_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_admin(user)
    row = (await db.execute(text("DELETE FROM tickets WHERE id = :id RETURNING id"), {"id": str(ticket_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Ticket not found")
    await db.commit()
    return {"success": True, "deletedTicketId": str(ticket_id), "error": None}


@incident_router.get("/{incident_id}/tickets")
async def incident_tickets(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    await _incident_exists(db, incident_id)
    rows = (await db.execute(text("""
        SELECT t.*, i.title AS incident_title
        FROM tickets t
        LEFT JOIN incidents i ON i.id = t.incident_id
        WHERE t.incident_id = :incident_id
        ORDER BY t.updated_at DESC
    """), {"incident_id": str(incident_id)})).mappings().all()
    return {"success": True, "tickets": [_ticket_row(row) for row in rows], "count": len(rows), "error": None}


@incident_router.post("/{incident_id}/tickets")
async def create_incident_ticket(
    incident_id: UUID,
    body: TicketCreateIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_ticket_write(user)
    ticket = await _create_ticket(db, body, user, incident_id=incident_id)
    return {"success": True, "ticket": ticket, "error": None}
