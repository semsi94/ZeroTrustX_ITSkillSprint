from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user
from db.session import get_db
from services.mitre_mapping_service import (
    analyze_incident_mitre,
    ensure_attack_data,
    incident_mitre_data,
    matrix as mitre_matrix,
    mitre_health,
    navigator_layer,
    sync_attack_data,
)


mitre_routes = APIRouter(tags=["mitre"])
incident_mitre_routes = APIRouter(tags=["mitre"])

router = APIRouter(prefix="/mitre", tags=["mitre"])
api_router = APIRouter(prefix="/api/mitre", tags=["mitre"])
incident_router = APIRouter(prefix="/incidents", tags=["mitre"])
api_incident_router = APIRouter(prefix="/api/incidents", tags=["mitre"])


def _require_write(user: dict) -> None:
    if user.get("role") in {"viewer", "degraded"}:
        raise HTTPException(status_code=403, detail="Viewer role is read-only")


def _require_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


class MitreLinkPatchIn(BaseModel):
    tactic_id: Optional[str] = Field(None, max_length=80)
    technique_id: Optional[str] = Field(None, max_length=80)
    subtechnique_id: Optional[str] = Field(None, max_length=80)
    technique_name: Optional[str] = Field(None, max_length=255)
    confidence_score: Optional[int] = Field(None, ge=0, le=100)
    reason: Optional[str] = Field(None, max_length=5000)
    matched_fields: Optional[dict] = None
    matched_evidence_ids: Optional[list[str]] = None
    mapping_source: Optional[str] = Field(None, max_length=50)


@mitre_routes.get("/tactics")
async def get_tactics(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    await ensure_attack_data(db)
    await db.commit()
    rows = (await db.execute(text("""
        SELECT * FROM mitre_tactics
        ORDER BY COALESCE(matrix_order, 999), tactic_id
    """))).mappings().all()
    return {"success": True, "tactics": [dict(row) | {"id": str(row["id"])} for row in rows], "error": None}


@mitre_routes.get("/techniques")
async def get_techniques(
    tactic_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    await ensure_attack_data(db)
    await db.commit()
    clauses = []
    params = {}
    if tactic_id:
        clauses.append("(mt.tactic_id = :tactic_id OR rel.tactic_id = :tactic_id)")
        params["tactic_id"] = tactic_id
    if search:
        clauses.append("(mt.technique_id ILIKE :search OR mt.subtechnique_id ILIKE :search OR mt.name ILIKE :search OR mt.description ILIKE :search)")
        params["search"] = f"%{search}%"
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    rows = (await db.execute(text(f"""
        SELECT DISTINCT ON (mt.technique_id, COALESCE(mt.subtechnique_id, ''), COALESCE(mt.tactic_id, '')) mt.*
        FROM mitre_techniques mt
        LEFT JOIN mitre_technique_tactics rel
          ON rel.technique_id = mt.technique_id
         AND COALESCE(rel.subtechnique_id, '') = COALESCE(mt.subtechnique_id, '')
        {where}
        ORDER BY mt.technique_id, COALESCE(mt.subtechnique_id, ''), COALESCE(mt.tactic_id, ''), mt.name
        LIMIT 1000
    """), params)).mappings().all()
    return {"success": True, "techniques": [dict(row) | {"id": str(row["id"])} for row in rows], "count": len(rows), "error": None}


@mitre_routes.get("/matrix")
async def get_matrix(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    return await mitre_matrix(db)


@mitre_routes.get("/health")
async def get_mitre_health(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    return await mitre_health(db)


@mitre_routes.post("/sync")
async def sync_mitre(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    _require_admin(user)
    return await sync_attack_data(db)


@incident_mitre_routes.get("/{incident_id}/mitre")
async def get_incident_mitre(incident_id: UUID, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    return await incident_mitre_data(db, incident_id)


@incident_mitre_routes.post("/{incident_id}/mitre/analyze")
async def analyze_incident(incident_id: UUID, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    _require_write(user)
    try:
        return await analyze_incident_mitre(db, incident_id, user, persist=True)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@incident_mitre_routes.patch("/{incident_id}/mitre-links/{link_id}")
async def patch_mitre_link(
    incident_id: UUID,
    link_id: UUID,
    body: MitreLinkPatchIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    updates = ["updated_at = NOW()"]
    params: dict = {"incident_id": str(incident_id), "link_id": str(link_id)}
    for field in ("tactic_id", "technique_id", "subtechnique_id", "technique_name", "reason", "mapping_source"):
        value = getattr(body, field)
        if value is not None:
            updates.append(f"{field} = :{field}")
            params[field] = value
    if body.confidence_score is not None:
        updates.append("confidence_score = :confidence_score")
        updates.append("confidence = :confidence")
        params["confidence_score"] = body.confidence_score
        params["confidence"] = body.confidence_score / 100
    typed = []
    if body.matched_fields is not None:
        updates.append("matched_fields = :matched_fields")
        params["matched_fields"] = body.matched_fields
        typed.append(bindparam("matched_fields", type_=JSONB))
    if body.matched_evidence_ids is not None:
        updates.append("matched_evidence_ids = :matched_evidence_ids")
        params["matched_evidence_ids"] = body.matched_evidence_ids
        typed.append(bindparam("matched_evidence_ids", type_=JSONB))
    stmt = text(f"""
        UPDATE incident_mitre_links
        SET {', '.join(updates)}
        WHERE id = :link_id AND incident_id = :incident_id
        RETURNING *
    """)
    if typed:
        stmt = stmt.bindparams(*typed)
    row = (await db.execute(stmt, params)).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="MITRE mapping not found")
    await db.commit()
    return await incident_mitre_data(db, incident_id)


@incident_mitre_routes.get("/{incident_id}/mitre/navigator-layer")
async def get_navigator_layer(incident_id: UUID, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    if user.get("role") in {"degraded"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return navigator_layer_result(await navigator_layer(db, incident_id))


def navigator_layer_result(layer: dict) -> dict:
    return layer


router.include_router(mitre_routes)
api_router.include_router(mitre_routes)
incident_router.include_router(incident_mitre_routes)
api_incident_router.include_router(incident_mitre_routes)
