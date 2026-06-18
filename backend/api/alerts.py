from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user, envelope
from db.session import get_db

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    clauses = []
    params: dict = {"limit": limit}
    if src_ip:
        clauses.append("src_ip = :src_ip")
        params["src_ip"] = src_ip
    if dest_ip:
        clauses.append("dest_ip = :dest_ip")
        params["dest_ip"] = dest_ip
    if source:
        clauses.append("source_system = :source")
        params["source"] = source
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    rows = (await db.execute(text(f"""
        SELECT id, incident_id, source_system, event_type, src_ip, dest_ip,
               username, hostname, signature, severity, event_time
        FROM alerts {where}
        ORDER BY event_time DESC NULLS LAST, created_at DESC
        LIMIT :limit
    """), params)).mappings().all()

    items = [
        {
            "id": str(r["id"]),
            "incident_id": str(r["incident_id"]) if r["incident_id"] else None,
            "source_system": r["source_system"],
            "event_type": r["event_type"],
            "src_ip": r["src_ip"],
            "dest_ip": r["dest_ip"],
            "username": r["username"],
            "hostname": r["hostname"],
            "signature": r["signature"],
            "severity": r["severity"],
            "event_time": r["event_time"].isoformat() if r["event_time"] else None,
        }
        for r in rows
    ]
    return envelope(items)
