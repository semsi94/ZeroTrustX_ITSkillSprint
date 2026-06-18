from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from adapters.abuseipdb_adapter import AbuseIpdbAdapter
from adapters.virustotal_adapter import VirusTotalAdapter
from api.deps import current_user, require_recent_mfa
from config import write_env_value
from db.session import get_db
from services.reputation_service import (
    observations_for_ip,
    enqueue_or_cache_ips,
    enrich_from_events,
    enrich_ip_now,
    get_cached_reputation,
    incident_ip_reputation,
    is_public_ip,
    provider_status,
)

router = APIRouter(prefix="/api/reputation", tags=["reputation"])


class EnrichIn(BaseModel):
    ips: list[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    force: bool = False


class EnrichEventsIn(BaseModel):
    events: list[dict] = Field(default_factory=list)
    incident_id: Optional[str] = None
    source_system: str = "investigation"
    force: bool = False


class ReputationSettingsIn(BaseModel):
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    enabled: Optional[bool] = None
    auto_incident_enabled: Optional[bool] = None


def _require_write(user: dict) -> None:
    if user.get("role") in {"viewer", "degraded"}:
        raise HTTPException(status_code=403, detail="Viewer role is read-only")


def _require_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")


@router.get("/ip/{ip}")
async def get_ip_reputation(ip: str, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    if not is_public_ip(ip):
        return {"success": True, "ip": ip, "reputation": None, "skipped_private": True, "error": None}
    rep = await get_cached_reputation(db, ip)
    return {"success": True, "ip": ip, "reputation": rep, "error": None}


@router.post("/ip/{ip}/refresh")
async def refresh_ip(ip: str, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    _require_write(user)
    if not is_public_ip(ip):
        raise HTTPException(status_code=400, detail="Private, local, reserved, or invalid IPs are not enriched")
    return await enrich_ip_now(db, ip, force=True)


@router.post("/enrich")
async def enrich_ips(body: EnrichIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    _require_write(user)
    return await enqueue_or_cache_ips(db, body.ips, incident_id=body.incident_id, source_system="manual", force=body.force)


@router.post("/enrich-from-events")
async def enrich_events(body: EnrichEventsIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    _require_write(user)
    return await enrich_from_events(db, body.events, incident_id=body.incident_id, source_system=body.source_system, force=body.force)


@router.get("/observations/{ip}")
async def get_observations(ip: str, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    return await observations_for_ip(db, ip)


@router.get("/provider-status")
async def get_provider_status(user: dict = Depends(current_user)):
    return provider_status()


@router.post("/sync-recent-ips")
async def sync_recent_ips(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    _require_write(user)
    # Prioritize incident evidence IPs; cap the batch so a lab dashboard never floods providers.
    from sqlalchemy import text

    rows = (await db.execute(text("""
        SELECT source_ip, destination_ip
        FROM evidence
        WHERE collected_at >= NOW() - INTERVAL '7 days'
        ORDER BY collected_at DESC
        LIMIT 1000
    """))).mappings().all()
    ips = []
    for row in rows:
        ips.extend([row.get("source_ip"), row.get("destination_ip")])
    return await enqueue_or_cache_ips(db, ips, source_system="recent_evidence")


@router.post("/settings")
async def save_reputation_settings(body: ReputationSettingsIn, user: dict = Depends(require_recent_mfa)):
    _require_admin(user)
    values = {}
    if body.abuseipdb_api_key is not None:
        values["ABUSEIPDB_API_KEY"] = body.abuseipdb_api_key
    if body.virustotal_api_key is not None:
        values["VIRUSTOTAL_API_KEY"] = body.virustotal_api_key
    if body.enabled is not None:
        values["IP_REPUTATION_ENABLED"] = str(bool(body.enabled)).lower()
    if body.auto_incident_enabled is not None:
        values["IP_REPUTATION_AUTO_INCIDENT_ENABLED"] = str(bool(body.auto_incident_enabled)).lower()
    for key, value in values.items():
        write_env_value(key, value)
    return provider_status()


@router.post("/test/abuseipdb")
async def test_abuseipdb(user: dict = Depends(require_recent_mfa)):
    _require_admin(user)
    result = AbuseIpdbAdapter().test_connection()
    return {"success": bool(result.get("success")), "provider": "abuseipdb", "configured": bool(result.get("configured")), "error": result.get("error")}


@router.post("/test/virustotal")
async def test_virustotal(user: dict = Depends(require_recent_mfa)):
    _require_admin(user)
    result = VirusTotalAdapter().test_connection()
    return {"success": bool(result.get("success")), "provider": "virustotal", "configured": bool(result.get("configured")), "error": result.get("error")}


@router.get("/queue-status")
async def queue_status(user: dict = Depends(current_user)):
    return {"success": True, "status": "available", "queue": "celery", "error": None}


@router.get("/recent")
async def recent_reputation(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    from sqlalchemy import text
    from services.reputation_service import reputation_to_dict

    rows = (await db.execute(text("""
        SELECT * FROM ip_reputation
        ORDER BY last_checked_at DESC NULLS LAST, last_seen_at DESC
        LIMIT 100
    """))).mappings().all()
    include_raw = user.get("role") == "admin"
    return {"success": True, "items": [reputation_to_dict(row, include_raw=include_raw) for row in rows], "error": None}


incident_router = APIRouter(prefix="/api/incidents", tags=["reputation"])


@incident_router.get("/{incident_id}/ip-reputation")
async def get_incident_reputation(incident_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    return await incident_ip_reputation(db, incident_id, include_raw=user.get("role") == "admin")
