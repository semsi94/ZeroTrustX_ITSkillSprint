import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user
from db.session import get_db
from services.mitre_mapping_service import analyze_incident_mitre


router = APIRouter(prefix="/api/alerts", tags=["alerts"])
log = logging.getLogger(__name__)


class ExternalAlertIn(BaseModel):
    source_system: str = Field("splunk", max_length=80)
    source_event_id: Optional[str] = Field(None, max_length=255)
    rule_name: str = Field(..., min_length=1, max_length=500)
    severity: Optional[str] = Field("medium", max_length=40)
    entities: dict = Field(default_factory=dict)
    raw_json: dict = Field(default_factory=dict)
    trigger_time: Optional[str] = None
    linked_incident_id: Optional[UUID] = None


def _can_ingest(user: dict) -> bool:
    return user.get("role") in {"admin", "soc_analyst", "senior_analyst", "analyst"}


def _time_bucket(value: Optional[str]) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
    except Exception:
        return str(value)[:13]


def _dedupe_key(body: ExternalAlertIn) -> str:
    entities = body.entities or {}
    seed = {
        "source_system": body.source_system.lower(),
        "source_event_id": body.source_event_id,
        "rule_name": body.rule_name.lower(),
        "source_ip": entities.get("source_ip") or entities.get("src_ip"),
        "user": entities.get("user") or entities.get("username") or entities.get("email"),
        "host": entities.get("host") or entities.get("hostname"),
        "bucket": _time_bucket(body.trigger_time),
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _external_alert_to_dict(row) -> dict:
    return {
        "id": str(row["id"]),
        "source_system": row.get("source_system"),
        "source_event_id": row.get("source_event_id"),
        "rule_name": row.get("rule_name"),
        "severity": row.get("severity"),
        "raw_json": row.get("raw_json"),
        "dedupe_key": row.get("dedupe_key"),
        "ingested_at": row["ingested_at"].isoformat() if row.get("ingested_at") else None,
        "linked_incident_id": str(row["linked_incident_id"]) if row.get("linked_incident_id") else None,
    }


@router.get("/external")
async def list_external_alerts(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    rows = (await db.execute(text("""
        SELECT * FROM external_alerts
        ORDER BY ingested_at DESC
        LIMIT 200
    """))).mappings().all()
    return {"success": True, "alerts": [_external_alert_to_dict(row) for row in rows], "count": len(rows), "error": None}


@router.post("/external")
async def ingest_external_alert(
    body: ExternalAlertIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    if not _can_ingest(user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    dedupe_key = _dedupe_key(body)
    existing = (await db.execute(text("""
        SELECT * FROM external_alerts
        WHERE dedupe_key = :dedupe_key
        LIMIT 1
    """), {"dedupe_key": dedupe_key})).mappings().first()
    if existing:
        return {
            "success": True,
            "alert": _external_alert_to_dict(existing),
            "deduplicated": True,
            "error": None,
        }

    raw = dict(body.raw_json or {})
    raw.setdefault("entities", body.entities)
    raw.setdefault("trigger_time", body.trigger_time)
    row = (await db.execute(text("""
        INSERT INTO external_alerts (
            source_system, source_event_id, rule_name, severity, raw_json,
            dedupe_key, linked_incident_id
        )
        VALUES (
            :source_system, :source_event_id, :rule_name, :severity, :raw_json,
            :dedupe_key, :linked_incident_id
        )
        RETURNING *
    """).bindparams(bindparam("raw_json", type_=JSONB)), {
        "source_system": body.source_system.lower(),
        "source_event_id": body.source_event_id,
        "rule_name": body.rule_name,
        "severity": (body.severity or "medium").lower(),
        "raw_json": raw,
        "dedupe_key": dedupe_key,
        "linked_incident_id": str(body.linked_incident_id) if body.linked_incident_id else None,
    })).mappings().first()
    await db.execute(text("""
        INSERT INTO event_outbox (event_type, aggregate_type, aggregate_id, payload_json)
        VALUES ('alert.ingested', 'external_alert', :alert_id, :payload)
    """).bindparams(bindparam("payload", type_=JSONB)), {
        "alert_id": str(row["id"]),
        "payload": {"linked_incident_id": str(body.linked_incident_id) if body.linked_incident_id else None},
    })
    if body.linked_incident_id:
        try:
            await analyze_incident_mitre(db, body.linked_incident_id, user, persist=True)
        except Exception as exc:
            log.warning("MITRE analysis after external alert ingest failed for incident %s: %s", body.linked_incident_id, exc)
            await db.commit()
    else:
        await db.commit()
    return {
        "success": True,
        "alert": _external_alert_to_dict(row),
        "deduplicated": False,
        "error": None,
    }
