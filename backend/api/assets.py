import ipaddress
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user, envelope
from db.session import get_db

router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_row(r) -> dict:
    return {
        "id": str(r["id"]),
        "hostname": r["hostname"],
        "ip": r["ip"],
        "zone": r["zone"],
        "owner": r["owner"],
        "asset_criticality": r["asset_criticality"],
        "is_placeholder": r["is_placeholder"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
    }


@router.get("")
async def list_assets(
    zone: Optional[str] = None,
    criticality: Optional[int] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 25,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    clauses = []
    params: dict = {}
    if zone:
        clauses.append("a.zone = :zone")
        params["zone"] = zone
    if criticality is not None:
        clauses.append("a.asset_criticality = :crit")
        params["crit"] = criticality
    if search:
        clauses.append("(a.hostname ILIKE :search OR a.ip ILIKE :search OR a.owner ILIKE :search)")
        params["search"] = f"%{search}%"
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    per_page = max(1, min(100, per_page))
    page = max(1, page)
    params["limit"] = per_page
    params["offset"] = (page - 1) * per_page

    total = (await db.execute(text(f"SELECT COUNT(*) FROM assets a {where}"), params)).scalar() or 0

    rows = (await db.execute(text(f"""
        SELECT a.*,
          (SELECT COUNT(*) FROM incidents i
           WHERE i.primary_asset_id = a.id
             AND i.status NOT IN ('closed','false_positive')) AS open_incident_count
        FROM assets a
        {where}
        ORDER BY a.asset_criticality DESC, a.hostname NULLS LAST
        LIMIT :limit OFFSET :offset
    """), params)).mappings().all()

    items = []
    for r in rows:
        d = _asset_row(r)
        d["open_incident_count"] = int(r["open_incident_count"])
        items.append(d)

    pages = max(1, (int(total) + per_page - 1) // per_page)
    return envelope({"items": items, "total": int(total), "page": page, "pages": pages})


class AssetIn(BaseModel):
    hostname: Optional[str] = None
    ip: str
    zone: Optional[str] = "unknown"
    owner: Optional[str] = None
    asset_criticality: int = Field(default=1, ge=1, le=5)


@router.post("")
async def create_or_update_asset(
    body: AssetIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP")

    res = await db.execute(text("""
        INSERT INTO assets (hostname, ip, zone, owner, asset_criticality, is_placeholder)
        VALUES (:hostname, :ip, :zone, :owner, :crit, FALSE)
        ON CONFLICT (ip) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            zone = EXCLUDED.zone,
            owner = EXCLUDED.owner,
            asset_criticality = EXCLUDED.asset_criticality,
            is_placeholder = FALSE,
            updated_at = NOW()
        RETURNING *
    """), {
        "hostname": body.hostname or body.ip,
        "ip": body.ip,
        "zone": body.zone or "unknown",
        "owner": body.owner,
        "crit": body.asset_criticality,
    })
    row = res.mappings().first()
    await db.commit()
    return envelope(_asset_row(row))


@router.get("/{asset_id}")
async def get_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    row = (await db.execute(text("SELECT * FROM assets WHERE id = :id"),
                            {"id": str(asset_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")

    incidents = (await db.execute(text("""
        SELECT id, title, severity, status, first_seen, last_seen
        FROM incidents WHERE primary_asset_id = :id
        ORDER BY last_seen DESC
    """), {"id": str(asset_id)})).mappings().all()

    alerts = (await db.execute(text("""
        SELECT id, incident_id, source_system, signature, src_ip, dest_ip, event_time, severity
        FROM alerts
        WHERE src_ip = :ip OR dest_ip = :ip
        ORDER BY event_time DESC NULLS LAST
        LIMIT 200
    """), {"ip": row["ip"]})).mappings().all()

    active_actions = (await db.execute(text("""
        SELECT id, action_type, target, status, initiated_at, executed_at
        FROM response_actions
        WHERE target = :ip AND status NOT IN ('reverted','failed')
        ORDER BY initiated_at DESC
    """), {"ip": row["ip"]})).mappings().all()

    c24 = (await db.execute(text("""
        SELECT COUNT(*) FROM alerts WHERE (src_ip = :ip OR dest_ip = :ip)
        AND event_time >= NOW() - INTERVAL '24 hours'
    """), {"ip": row["ip"]})).scalar() or 0

    c7 = (await db.execute(text("""
        SELECT COUNT(*) FROM alerts WHERE (src_ip = :ip OR dest_ip = :ip)
        AND event_time >= NOW() - INTERVAL '7 days'
    """), {"ip": row["ip"]})).scalar() or 0

    data = _asset_row(row)
    data["incidents"] = [
        {
            "id": str(i["id"]), "title": i["title"], "severity": i["severity"],
            "status": i["status"],
            "first_seen": i["first_seen"].isoformat() if i["first_seen"] else None,
            "last_seen": i["last_seen"].isoformat() if i["last_seen"] else None,
        } for i in incidents
    ]
    data["alerts"] = [
        {
            "id": str(a["id"]),
            "incident_id": str(a["incident_id"]) if a["incident_id"] else None,
            "source_system": a["source_system"],
            "signature": a["signature"],
            "src_ip": a["src_ip"], "dest_ip": a["dest_ip"],
            "event_time": a["event_time"].isoformat() if a["event_time"] else None,
            "severity": a["severity"],
            "direction": "src" if a["src_ip"] == row["ip"] else "dest",
        } for a in alerts
    ]
    data["active_actions"] = [
        {
            "id": str(a["id"]),
            "action_type": a["action_type"],
            "target": a["target"],
            "status": a["status"],
            "initiated_at": a["initiated_at"].isoformat() if a["initiated_at"] else None,
            "executed_at": a["executed_at"].isoformat() if a["executed_at"] else None,
        } for a in active_actions
    ]
    data["event_count_24h"] = int(c24)
    data["event_count_7d"] = int(c7)

    return envelope(data)
