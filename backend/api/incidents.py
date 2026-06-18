import asyncio
import hashlib
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy import Text
from sqlalchemy.ext.asyncio import AsyncSession

from adapters.splunk_adapter import SplunkAdapter, ensure_search_prefix
from api.deps import current_user, envelope, require_recent_mfa
from core.mitre import auto_map_mitre
from core.splunk_cache import event_hash, parse_time
from db.session import get_db
from services.mitre_mapping_service import analyze_incident_mitre

router = APIRouter(prefix="/incidents", tags=["incidents"])
api_router = APIRouter(prefix="/api/incidents", tags=["incidents"])
log = logging.getLogger(__name__)


VALID_STATUSES = {
    "draft",
    "pending_evidence",
    "pending_approval",
    "new",
    "triage",
    "in_review",
    "investigating",
    "contained",
    "monitoring",
    "resolved",
    "closed",
    "rejected",
    "false_positive",
}
API_STATUSES = {
    "draft",
    "pending_evidence",
    "pending_approval",
    "new",
    "triage",
    "in_review",
    "investigating",
    "contained",
    "monitoring",
    "resolved",
    "closed",
    "rejected",
}
WORKFLOW_STATUSES = {"open", "assigned", "in_progress", "waiting", "escalated", "resolved", "closed", "cancelled"}
WORKFLOW_PRIORITIES = {"critical", "high", "medium", "low"}
CATEGORY_VALUES = {
    "authentication",
    "network",
    "web",
    "endpoint",
    "firewall",
    "malware",
    "data_exfiltration",
    "reconnaissance",
    "policy_violation",
    "other",
}
DETECTION_SOURCES = {"manual", "splunk_alert", "splunk_report", "investigation"}
SEVERITY_TO_INT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}
INT_TO_SEVERITY = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "informational"}
VERDICTS = {"undecided", "true_positive", "false_positive", "benign_positive", "duplicate", "needs_more_evidence"}


def _require_write(user: dict) -> None:
    if user.get("role") in {"viewer", "degraded"}:
        raise HTTPException(status_code=403, detail="Viewer role is read-only")


def _require_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


def _clean_token(value: Optional[str], default: str) -> str:
    return str(value or default).strip().lower().replace(" ", "_").replace("-", "_")


def _parse_datetime(value: Optional[str]):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid datetime value")


def _sla_state(row: dict) -> str:
    due = row.get("resolve_due_at") or row.get("sla_due_at")
    if not due:
        return "no_sla"
    if isinstance(due, str):
        due = _parse_datetime(due)
    now = datetime.now(timezone.utc)
    if due < now:
        return "breached"
    if due - now <= timedelta(hours=4):
        return "due_soon"
    return "on_track"


@router.get("")
async def list_incidents(
    severity: Optional[int] = None,
    status: Optional[str] = None,
    zone: Optional[str] = None,
    source: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 25,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    clauses = []
    params: dict = {}
    if severity is not None:
        clauses.append("i.severity = :severity")
        params["severity"] = severity
    if status:
        clauses.append("i.status = :status")
        params["status"] = status
    if zone:
        clauses.append("a.zone = :zone")
        params["zone"] = zone
    if source:
        clauses.append(":source = ANY(i.source_systems)")
        params["source"] = source
    if from_date:
        clauses.append("i.first_seen >= :from_date")
        params["from_date"] = from_date
    if to_date:
        clauses.append("i.first_seen <= :to_date")
        params["to_date"] = to_date
    if search:
        clauses.append("(i.title ILIKE :search OR a.hostname ILIKE :search OR a.ip ILIKE :search)")
        params["search"] = f"%{search}%"

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    per_page = max(1, min(100, per_page))
    page = max(1, page)
    offset = (page - 1) * per_page
    params["limit"] = per_page
    params["offset"] = offset

    total = (await db.execute(text(f"""
        SELECT COUNT(*) FROM incidents i
        LEFT JOIN assets a ON a.id = i.primary_asset_id
        {where}
    """), params)).scalar() or 0

    rows = (await db.execute(text(f"""
        SELECT i.*, a.hostname AS asset_hostname, a.ip AS asset_ip, a.zone AS asset_zone,
               a.asset_criticality AS asset_criticality,
               rep.top_ip_reputation
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.primary_asset_id
        LEFT JOIN LATERAL (
            SELECT jsonb_agg(jsonb_build_object(
                'ip_address', r.ip_address,
                'overall_verdict', r.overall_verdict,
                'overall_score', r.overall_score,
                'abuseipdb_score', r.abuseipdb_score,
                'virustotal_malicious', r.virustotal_malicious,
                'virustotal_suspicious', r.virustotal_suspicious,
                'last_checked_at', r.last_checked_at
            ) ORDER BY r.overall_score DESC) AS top_ip_reputation
            FROM incident_ip_reputation_links l
            JOIN ip_reputation r ON r.id = l.reputation_id
            WHERE l.incident_id = i.id
            LIMIT 3
        ) rep ON TRUE
        {where}
        ORDER BY i.last_seen DESC
        LIMIT :limit OFFSET :offset
    """), params)).mappings().all()

    items = [_incident_row_to_dict(r) for r in rows]
    pages = max(1, (int(total) + per_page - 1) // per_page)
    return envelope({"items": items, "total": int(total), "page": page, "pages": pages})


def _incident_row_to_dict(r) -> dict:
    return {
        "id": str(r["id"]),
        "title": r["title"],
        "severity": r["severity"],
        "confidence": r["confidence"],
        "status": r["status"],
        "cia_c": r["cia_c"],
        "cia_i": r["cia_i"],
        "cia_a": r["cia_a"],
        "mitre_tactic": r["mitre_tactic"],
        "mitre_technique": r["mitre_technique"],
        "primary_asset_id": str(r["primary_asset_id"]) if r["primary_asset_id"] else None,
        "response_level": r["response_level"],
        "source_systems": list(r["source_systems"]) if r["source_systems"] else [],
        "priority_score": r["priority_score"],
        "is_false_positive": r["is_false_positive"],
        "first_seen": r["first_seen"].isoformat() if r["first_seen"] else None,
        "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
        "triaged_at": r["triaged_at"].isoformat() if r["triaged_at"] else None,
        "contained_at": r["contained_at"].isoformat() if r["contained_at"] else None,
        "closed_at": r["closed_at"].isoformat() if r["closed_at"] else None,
        "analyst_notes": r["analyst_notes"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "asset_hostname": r.get("asset_hostname"),
        "asset_ip": r.get("asset_ip"),
        "asset_zone": r.get("asset_zone"),
        "asset_criticality": r.get("asset_criticality"),
        "ip_reputation": r.get("top_ip_reputation") or [],
    }


@router.get("/{incident_id}")
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    row = (await db.execute(text("""
        SELECT i.*, a.id AS asset_id, a.hostname AS asset_hostname, a.ip AS asset_ip,
               a.zone AS asset_zone, a.asset_criticality, a.owner AS asset_owner
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.primary_asset_id
        WHERE i.id = :id
    """), {"id": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = (await db.execute(text("""
        SELECT * FROM alerts WHERE incident_id = :id ORDER BY event_time ASC NULLS LAST, created_at ASC
    """), {"id": str(incident_id)})).mappings().all()

    actions = (await db.execute(text("""
        SELECT * FROM response_actions WHERE incident_id = :id ORDER BY initiated_at DESC
    """), {"id": str(incident_id)})).mappings().all()

    evidence = (await db.execute(text("""
        SELECT * FROM evidence WHERE incident_id = :id ORDER BY collected_at DESC
    """), {"id": str(incident_id)})).mappings().all()

    source_rows = (await db.execute(text("""
        SELECT COALESCE(source_system, 'unknown') AS source_system, COUNT(*) AS count
        FROM alerts
        WHERE incident_id = :id
        GROUP BY COALESCE(source_system, 'unknown')
    """), {"id": str(incident_id)})).mappings().all()
    source_breakdown = {r["source_system"]: int(r["count"]) for r in source_rows}

    data = _incident_row_to_dict(row)
    data["primary_asset"] = (
        {
            "id": str(row["asset_id"]),
            "hostname": row["asset_hostname"],
            "ip": row["asset_ip"],
            "zone": row["asset_zone"],
            "asset_criticality": row["asset_criticality"],
            "owner": row["asset_owner"],
        }
        if row["asset_id"] else None
    )
    data["alerts"] = [_alert_to_dict(a) for a in alerts]
    data["response_actions"] = [_action_to_dict(a) for a in actions]
    data["evidence"] = [_evidence_to_dict(e) for e in evidence]
    data["source_breakdown"] = source_breakdown

    return envelope(data)


def _alert_to_dict(a) -> dict:
    return {
        "id": str(a["id"]),
        "incident_id": str(a["incident_id"]) if a["incident_id"] else None,
        "source_system": a["source_system"],
        "event_type": a["event_type"],
        "src_ip": a["src_ip"],
        "dest_ip": a["dest_ip"],
        "username": a["username"],
        "hostname": a["hostname"],
        "signature": a["signature"],
        "category": a["category"],
        "zone": a["zone"],
        "severity": a["severity"],
        "confidence": a["confidence"],
        "cia_c": a["cia_c"],
        "cia_i": a["cia_i"],
        "cia_a": a["cia_a"],
        "mitre_tactic": a["mitre_tactic"],
        "raw_ref": a["raw_ref"],
        "raw_payload": a["raw_payload"],
        "event_time": a["event_time"].isoformat() if a["event_time"] else None,
        "created_at": a["created_at"].isoformat() if a["created_at"] else None,
    }


def _action_to_dict(a) -> dict:
    return {
        "id": str(a["id"]),
        "incident_id": str(a["incident_id"]) if a["incident_id"] else None,
        "action_type": a["action_type"],
        "target": a["target"],
        "alias": a["alias"],
        "status": a["status"],
        "initiated_by": a["initiated_by"],
        "approved_by": a["approved_by"],
        "initiated_at": a["initiated_at"].isoformat() if a["initiated_at"] else None,
        "executed_at": a["executed_at"].isoformat() if a["executed_at"] else None,
        "reverted_at": a["reverted_at"].isoformat() if a["reverted_at"] else None,
        "output": a["output"],
        "error_message": a["error_message"],
        "rollback_available": a["rollback_available"],
    }


def _evidence_to_dict(e) -> dict:
    return {
        "id": str(e["id"]),
        "incident_id": str(e["incident_id"]) if e["incident_id"] else None,
        "type": e["type"],
        "path_or_ref": e["path_or_ref"],
        "source_system": e.get("source_system") or e.get("source"),
        "source_ref": e.get("source_ref") or e.get("path_or_ref"),
        "query_sid": e.get("query_sid"),
        "search_id": e.get("search_id"),
        "content_hash": e.get("content_hash") or e.get("event_hash") or e.get("hash"),
        "hash": e["hash"],
        "collected_by": e["collected_by"],
        "collector_id": e.get("collector_id"),
        "collected_at": e["collected_at"].isoformat() if e["collected_at"] else None,
        "raw_data": e["raw_data"],
    }


class StatusIn(BaseModel):
    status: str
    notes: Optional[str] = None


@router.patch("/{incident_id}/status")
async def update_status(
    incident_id: UUID,
    body: StatusIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {sorted(VALID_STATUSES)}")

    cur = (await db.execute(text("SELECT status, triaged_at FROM incidents WHERE id = :id"),
                            {"id": str(incident_id)})).mappings().first()
    if not cur:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    set_parts = ["status = :status"]
    params: dict = {"id": str(incident_id), "status": body.status}
    if body.notes is not None:
        set_parts.append("analyst_notes = :notes")
        params["notes"] = body.notes
    if cur["status"] == "new" and body.status != "new" and cur["triaged_at"] is None:
        set_parts.append("triaged_at = :triaged_at")
        params["triaged_at"] = now
    if body.status == "contained":
        set_parts.append("contained_at = :contained_at")
        params["contained_at"] = now
    if body.status in ("closed", "false_positive"):
        set_parts.append("closed_at = :closed_at")
        params["closed_at"] = now
        set_parts.append("is_false_positive = :fp")
        params["fp"] = (body.status == "false_positive")

    await db.execute(text(f"UPDATE incidents SET {', '.join(set_parts)} WHERE id = :id"), params)
    await db.commit()
    return envelope({"id": str(incident_id), "status": body.status})


@router.get("/{incident_id}/timeline")
async def timeline(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    alerts = (await db.execute(text("""
        SELECT id, event_time, source_system, event_type, src_ip, dest_ip,
               username, hostname, signature, cia_c, cia_i, cia_a, raw_payload
        FROM alerts WHERE incident_id = :id
        ORDER BY event_time ASC NULLS LAST, created_at ASC
    """), {"id": str(incident_id)})).mappings().all()

    items = [
        {
            "id": str(a["id"]),
            "event_time": a["event_time"].isoformat() if a["event_time"] else None,
            "source_system": a["source_system"],
            "event_type": a["event_type"],
            "src_ip": a["src_ip"],
            "dest_ip": a["dest_ip"],
            "username": a["username"],
            "hostname": a["hostname"],
            "signature": a["signature"],
            "cia_c": a["cia_c"],
            "cia_i": a["cia_i"],
            "cia_a": a["cia_a"],
            "raw_payload": a["raw_payload"],
        }
        for a in alerts
    ]
    return envelope(items)


class BlockIpIn(BaseModel):
    target_ip: str
    alias: Optional[str] = None


@router.post("/{incident_id}/block-ip")
async def block_ip(
    incident_id: UUID,
    body: BlockIpIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    from config import get_settings
    settings = get_settings()
    if not all([settings.PFSENSE_HOST, settings.PFSENSE_USERNAME, settings.PFSENSE_PASSWORD]):
        raise HTTPException(status_code=412, detail="pfSense not configured")
    try:
        ipaddress.ip_address(body.target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    alias = body.alias or settings.PFSENSE_BLOCK_ALIAS
    res = await db.execute(text("""
        INSERT INTO response_actions
          (incident_id, action_type, target, alias, status, initiated_by, rollback_available)
        VALUES (:id, 'block_ip', :target, :alias, 'pending', :user, TRUE)
        RETURNING id
    """), {
        "id": str(incident_id),
        "target": body.target_ip,
        "alias": alias,
        "user": user["username"],
    })
    action_id = res.scalar_one()
    await db.commit()

    from workers.response_tasks import block_ip_task
    task = block_ip_task.delay(body.target_ip, str(incident_id), str(action_id), alias)

    return envelope({"action_id": str(action_id), "task_id": task.id})


@router.post("/{incident_id}/revert/{action_id}")
async def revert(
    incident_id: UUID,
    action_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    row = (await db.execute(text("""
        SELECT id, target, alias, rollback_available, status
        FROM response_actions WHERE id = :id AND incident_id = :iid
    """), {"id": str(action_id), "iid": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    if not row["rollback_available"]:
        raise HTTPException(status_code=409, detail="Rollback not available")

    await db.execute(text("""
        UPDATE response_actions SET rollback_available = FALSE, status = 'pending' WHERE id = :id
    """), {"id": str(action_id)})
    await db.commit()

    from workers.response_tasks import unblock_ip_task
    task = unblock_ip_task.delay(row["target"], str(action_id), row["alias"])
    return envelope({"task_id": task.id})


class CloseIn(BaseModel):
    notes: Optional[str] = None
    is_false_positive: bool = False


@router.post("/{incident_id}/close")
async def close_incident(
    incident_id: UUID,
    body: CloseIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    status_val = "false_positive" if body.is_false_positive else "closed"
    now = datetime.now(timezone.utc)
    res = await db.execute(text("""
        UPDATE incidents
        SET status = :s, closed_at = :t, is_false_positive = :fp,
            analyst_notes = COALESCE(:notes, analyst_notes)
        WHERE id = :id
        RETURNING id
    """), {"s": status_val, "t": now, "fp": body.is_false_positive,
           "notes": body.notes, "id": str(incident_id)})
    if res.scalar() is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    await db.commit()
    return envelope({"id": str(incident_id), "status": status_val})


def _severity_to_int(value) -> int:
    if isinstance(value, int):
        if 1 <= value <= 5:
            return value
        raise HTTPException(status_code=400, detail="Invalid severity")
    key = str(value or "medium").strip().lower()
    if key not in SEVERITY_TO_INT:
        raise HTTPException(status_code=400, detail="Invalid severity")
    return SEVERITY_TO_INT[key]


def _status_value(value: str) -> str:
    status = str(value or "pending_evidence").strip().lower().replace(" ", "_").replace("-", "_")
    if status not in API_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")
    return status


def _category_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    category = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if category not in CATEGORY_VALUES:
        raise HTTPException(status_code=400, detail="Invalid category")
    return category


def _detection_source_value(value: Optional[str]) -> str:
    source = str(value or "manual").strip().lower().replace(" ", "_").replace("-", "_")
    if source not in DETECTION_SOURCES:
        raise HTTPException(status_code=400, detail="Invalid detection source")
    return source


def _api_incident(row) -> dict:
    evidence_count = int(row.get("evidence_count") or 0)
    related_alert_count = int(row.get("related_alert_count") or 0)
    related_ticket_count = int(row.get("related_ticket_count") or 0)
    is_active = bool(row.get("is_active") or evidence_count > 0)
    activation_state = row.get("activation_state") or ("active" if is_active else "pending_evidence")
    return {
        "id": str(row["id"]),
        "title": row["title"],
        "description": row.get("description") or row.get("analyst_notes") or "",
        "severity": INT_TO_SEVERITY.get(int(row["severity"] or 3), "medium"),
        "severity_value": int(row["severity"] or 3),
        "status": row["status"],
        "state": activation_state,
        "activation_state": activation_state,
        "is_active": is_active,
        "category": row.get("category"),
        "source": row.get("source") or "analyst",
        "owner": row.get("owner"),
        "confidence": float(row.get("confidence") or 0),
        "mitre_tactic": row.get("mitre_tactic"),
        "mitre_technique": row.get("mitre_technique"),
        "mitre_technique_id": row.get("mitre_technique_id") or row.get("mitre_technique"),
        "mitre_technique_name": row.get("mitre_technique_name"),
        "mitre_confidence": float(row.get("mitre_confidence")) if row.get("mitre_confidence") is not None else None,
        "mitre_mapping_source": row.get("mitre_mapping_source") or "auto",
        "analyst_verdict": row.get("analyst_verdict") or "undecided",
        "verdict_reason": row.get("verdict_reason"),
        "verdict_by": row.get("verdict_by"),
        "verdict_at": row["verdict_at"].isoformat() if row.get("verdict_at") else None,
        "dedup_key": row.get("dedup_key"),
        "occurrence_count": int(row.get("occurrence_count") or 1),
        "linked_splunk_alert_id": row.get("linked_splunk_alert_id"),
        "linked_splunk_report_id": row.get("linked_splunk_report_id"),
        "detection_source": row.get("detection_source") or "manual",
        "entities": row.get("entities") or {},
        "tags": list(row.get("tags") or []),
        "notes": row.get("notes") or "",
        "approval_status": row.get("approval_status") or "approved",
        "approved_by": row.get("approved_by"),
        "approved_at": row["approved_at"].isoformat() if row.get("approved_at") else None,
        "source_ref": row.get("source_ref"),
        "source_hash": row.get("source_hash"),
        "priority": row.get("priority") or INT_TO_SEVERITY.get(int(row["severity"] or 3), "medium"),
        "queue": row.get("queue") or "SOC",
        "workflow_status": row.get("workflow_status") or "open",
        "sla_due_at": row["sla_due_at"].isoformat() if row.get("sla_due_at") else None,
        "first_ack_due_at": row["first_ack_due_at"].isoformat() if row.get("first_ack_due_at") else None,
        "resolve_due_at": row["resolve_due_at"].isoformat() if row.get("resolve_due_at") else None,
        "escalation_level": int(row.get("escalation_level") or 0),
        "requested_action": row.get("requested_action") or "",
        "resolution_notes": row.get("resolution_notes") or "",
        "close_reason": row.get("close_reason") or "",
        "sla_state": _sla_state(dict(row)),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": (row.get("updated_at") or row.get("last_seen")).isoformat() if (row.get("updated_at") or row.get("last_seen")) else None,
        "evidence_count": evidence_count,
        "related_alert_count": related_alert_count,
        "related_ticket_count": related_ticket_count,
    }


def _event_payload(event: dict, user: dict) -> dict:
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Evidence event must be an object")
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else event
    h = event.get("event_hash") or event_hash(event)
    source = event.get("source") or "splunk"
    return {
        "type": "splunk_event",
        "path_or_ref": event.get("id") or h,
        "hash": h,
        "event_hash": h,
        "event_time": parse_time(event.get("time") or event.get("_time")),
        "source": source,
        "source_system": event.get("source_system") or source,
        "source_ref": event.get("source_ref") or event.get("id") or event.get("_cd") or h,
        "query_sid": event.get("query_sid") or event.get("sid"),
        "search_id": event.get("search_id") or event.get("sid"),
        "content_hash": event.get("content_hash") or h,
        "index": event.get("index") or None,
        "sourcetype": event.get("sourcetype") or None,
        "host": event.get("host") or None,
        "source_ip": event.get("source_ip") or None,
        "destination_ip": event.get("destination_ip") or None,
        "user_email": event.get("email") or event.get("user") or None,
        "action": event.get("action") or None,
        "message": event.get("message") or None,
        "collected_by": user.get("username") or "analyst",
        "collector_id": user.get("id"),
        "raw_data": raw,
        "raw_event": raw,
    }


class IncidentCreateIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=300)
    description: str = ""
    severity: str | int = "medium"
    status: str = "pending_evidence"
    category: str = "other"
    source: str = "analyst"
    owner: Optional[str] = None
    linked_splunk_alert_id: Optional[str] = None
    linked_splunk_report_id: Optional[str] = None
    detection_source: str = "manual"
    entities: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None
    source_ref: Optional[str] = None
    source_hash: Optional[str] = None
    evidence: list[dict] = Field(default_factory=list)


class IncidentPatchIn(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=300)
    description: Optional[str] = None
    severity: Optional[str | int] = None
    status: Optional[str] = None
    category: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[list[str]] = None
    entities: Optional[dict] = None
    detection_source: Optional[str] = None
    notes: Optional[str] = None
    approval_status: Optional[str] = None
    analyst_verdict: Optional[str] = None
    verdict_reason: Optional[str] = None
    duplicate_of: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_confidence: Optional[float] = None
    mitre_mapping_source: Optional[str] = None


class IncidentWorkflowPatchIn(BaseModel):
    queue: Optional[str] = Field(None, max_length=120)
    owner: Optional[str] = Field(None, max_length=255)
    priority: Optional[str] = None
    workflow_status: Optional[str] = None
    sla_due_at: Optional[str] = None
    first_ack_due_at: Optional[str] = None
    resolve_due_at: Optional[str] = None
    escalation_level: Optional[int] = Field(None, ge=0, le=5)
    requested_action: Optional[str] = Field(None, max_length=3000)
    resolution_notes: Optional[str] = Field(None, max_length=5000)
    close_reason: Optional[str] = Field(None, max_length=3000)


class IncidentCommentIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)
    comment_type: str = Field("internal_note", max_length=50)


class ObservableIn(BaseModel):
    type: str = Field(..., max_length=50)
    value: str = Field(..., min_length=1, max_length=1000)
    is_ioc: bool = False
    is_sighted: bool = True


class IncidentMitreLinkIn(BaseModel):
    tactic_id: Optional[str] = Field(None, max_length=80)
    technique_id: str = Field(..., min_length=2, max_length=80)
    subtechnique_id: Optional[str] = Field(None, max_length=80)
    technique_name: Optional[str] = Field(None, max_length=255)
    confidence: Optional[float] = Field(None, ge=0, le=1)
    confidence_score: Optional[int] = Field(None, ge=0, le=100)
    reason: Optional[str] = Field(None, max_length=5000)
    matched_fields: Optional[dict] = None
    matched_evidence_ids: Optional[list[str]] = None
    mapping_source: str = Field("manual", max_length=50)


class EvidenceIn(BaseModel):
    event: dict


class EvidenceBulkIn(BaseModel):
    events: list[dict] = Field(default_factory=list, max_length=500)


async def _record_activity(
    db: AsyncSession,
    incident_id: str,
    activity_type: str,
    summary: str,
    user: Optional[dict] = None,
    metadata: Optional[dict] = None,
) -> None:
    await db.execute(text("""
        INSERT INTO incident_activity (incident_id, activity_type, summary, actor, metadata_json)
        VALUES (:incident_id, :activity_type, :summary, :actor, :metadata)
    """).bindparams(bindparam("metadata", type_=JSONB)), {
        "incident_id": str(incident_id),
        "activity_type": activity_type,
        "summary": summary,
        "actor": (user or {}).get("username"),
        "metadata": metadata or {},
    }) 


async def _record_outbox(
    db: AsyncSession,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: Optional[dict] = None,
) -> None:
    await db.execute(text("""
        INSERT INTO event_outbox (event_type, aggregate_type, aggregate_id, payload_json)
        VALUES (:event_type, :aggregate_type, :aggregate_id, :payload)
    """).bindparams(bindparam("payload", type_=JSONB)), {
        "event_type": event_type,
        "aggregate_type": aggregate_type,
        "aggregate_id": str(aggregate_id),
        "payload": payload or {},
    })


async def _record_audit(
    db: AsyncSession,
    user: Optional[dict],
    action: str,
    object_type: str,
    object_id: Optional[str],
    outcome: str = "success",
) -> None:
    await db.execute(text("""
        INSERT INTO audit_log (actor_id, action, object_type, object_id, outcome)
        VALUES (:actor_id, :action, :object_type, :object_id, :outcome)
    """), {
        "actor_id": (user or {}).get("id") or (user or {}).get("username"),
        "action": action,
        "object_type": object_type,
        "object_id": str(object_id) if object_id else None,
        "outcome": outcome,
    })


def _extract_observables_from_event(event: dict) -> list[tuple[str, str]]:
    raw = event.get("raw_event") or event.get("raw") or event
    pairs: list[tuple[str, str]] = []

    def add(kind: str, value) -> None:
        text_value = str(value or "").strip()
        if text_value:
            pairs.append((kind, text_value[:1000]))

    for key in ("source_ip", "src_ip", "client_ip"):
        add("ip", event.get(key) or raw.get(key))
    for key in ("destination_ip", "dest_ip", "dst_ip"):
        add("ip", event.get(key) or raw.get(key))
    add("user", event.get("user_email") or event.get("email") or event.get("user") or raw.get("user") or raw.get("username"))
    add("host", event.get("host") or raw.get("host") or raw.get("hostname"))
    add("url", raw.get("url") or raw.get("uri") or raw.get("request_url"))
    add("domain", raw.get("domain") or raw.get("dest_domain"))
    add("hash", raw.get("hash") or raw.get("file_hash") or raw.get("sha256") or raw.get("md5"))
    add("file", raw.get("file") or raw.get("filename") or raw.get("process"))
    return list(dict.fromkeys(pairs))


async def _upsert_observables(db: AsyncSession, incident_id: str, events: list[dict]) -> int:
    count = 0
    for event in events:
        for kind, value in _extract_observables_from_event(event):
            exists = (await db.execute(text("""
                SELECT id FROM observables
                WHERE incident_id = :incident_id AND type = :type AND lower(value) = lower(:value)
                LIMIT 1
            """), {"incident_id": incident_id, "type": kind, "value": value})).scalar()
            if exists:
                continue
            await db.execute(text("""
                INSERT INTO observables (incident_id, type, value, is_sighted, first_seen_at)
                VALUES (:incident_id, :type, :value, TRUE, NOW())
            """), {"incident_id": incident_id, "type": kind, "value": value})
            count += 1
    return count


def _comment_to_dict(row) -> dict:
    return {
        "id": str(row["id"]),
        "incident_id": str(row["incident_id"]),
        "body": row.get("body") or "",
        "comment_type": row.get("comment_type") or "internal_note",
        "created_by": row.get("created_by") or "",
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
    }


def _activity_to_dict(row) -> dict:
    return {
        "id": str(row["id"]),
        "incident_id": str(row["incident_id"]),
        "activity_type": row.get("activity_type"),
        "summary": row.get("summary") or "",
        "actor": row.get("actor") or "",
        "metadata": row.get("metadata_json") or {},
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
    }


async def _insert_evidence(db: AsyncSession, incident_id: str, events: list[dict], user: dict) -> int:
    added = 0
    stmt = text("""
        INSERT INTO evidence (
            incident_id, type, path_or_ref, hash, event_hash, event_time,
            source, source_system, source_ref, query_sid, search_id, content_hash,
            "index", sourcetype, host, source_ip, destination_ip,
            user_email, action, message, collected_by, collector_id, raw_data, raw_event
        )
        VALUES (
            :incident_id, :type, :path_or_ref, :hash, :event_hash, :event_time,
            :source, :source_system, :source_ref, :query_sid, :search_id, :content_hash,
            :index, :sourcetype, :host, :source_ip, :destination_ip,
            :user_email, :action, :message, :collected_by, :collector_id, :raw_data, :raw_event
        )
    """).bindparams(bindparam("raw_data", type_=JSONB), bindparam("raw_event", type_=JSONB))
    for event in events:
        payload = _event_payload(event, user)
        payload["incident_id"] = incident_id
        duplicate = (await db.execute(text("""
            SELECT id FROM evidence
            WHERE incident_id = :incident_id AND event_hash = :event_hash
            LIMIT 1
        """), {"incident_id": incident_id, "event_hash": payload["event_hash"]})).scalar()
        if duplicate:
            continue
        await db.execute(stmt, payload)
        added += 1
    if added:
        observables_added = await _upsert_observables(db, incident_id, events)
        mitre_parts = []
        for event in events:
            mitre_parts.extend([
                event.get("message") or event.get("signature") or "",
                event.get("action") or "",
                event.get("category") or event.get("event_category") or "",
                event.get("sourcetype") or "",
            ])
        mapping = auto_map_mitre(*mitre_parts)
        await db.execute(text("""
            UPDATE incidents
            SET updated_at = NOW(),
                last_seen = NOW(),
                evidence_count = COALESCE(evidence_count, 0) + :added,
                mitre_tactic = COALESCE(mitre_tactic, :mitre_tactic),
                mitre_technique_id = COALESCE(mitre_technique_id, :mitre_technique_id),
                mitre_technique = COALESCE(mitre_technique, :mitre_technique_id),
                mitre_technique_name = COALESCE(mitre_technique_name, :mitre_technique_name),
                mitre_confidence = COALESCE(mitre_confidence, :mitre_confidence),
                activation_state = CASE
                    WHEN approval_status = 'approved' THEN 'active'
                    ELSE activation_state
                END,
                is_active = CASE
                    WHEN approval_status = 'approved' THEN TRUE
                    ELSE is_active
                END,
                status = CASE
                    WHEN approval_status = 'approved' AND status IN ('draft', 'pending_evidence') THEN 'new'
                    ELSE status
                END
            WHERE id = :id
        """), {"id": incident_id, "added": added, **mapping})
        await _record_activity(
            db,
            incident_id,
            "evidence_added",
            f"{added} evidence item{'s' if added != 1 else ''} promoted to incident",
            user,
            {"added": added, "observables_added": observables_added},
        )
        await _record_outbox(db, "evidence.promoted", "incident", incident_id, {"added": added})
        try:
            await analyze_incident_mitre(db, UUID(str(incident_id)), user, persist=True)
        except Exception as exc:
            log.warning("MITRE analysis after evidence promotion failed for incident %s: %s", incident_id, exc)
    return added


@api_router.get("")
async def api_list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    clauses = []
    params: dict = {"limit": limit}
    if status:
        clauses.append("i.status = :status")
        params["status"] = _status_value(status)
    if severity:
        clauses.append("i.severity = :severity")
        params["severity"] = _severity_to_int(severity)
    if source:
        clauses.append("i.source = :source")
        params["source"] = source
    if search:
        clauses.append("(i.title ILIKE :search OR i.description ILIKE :search OR i.analyst_notes ILIKE :search OR i.owner ILIKE :search)")
        params["search"] = f"%{search}%"
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    rows = (await db.execute(text(f"""
        SELECT i.*,
               COUNT(DISTINCT e.id) AS evidence_count,
               COUNT(DISTINCT a.id) + COUNT(DISTINCT ea.id) AS related_alert_count,
               COUNT(DISTINCT t.id) AS related_ticket_count
        FROM incidents i
        LEFT JOIN evidence e ON e.incident_id = i.id
        LEFT JOIN alerts a ON a.incident_id = i.id
        LEFT JOIN external_alerts ea ON ea.linked_incident_id = i.id
        LEFT JOIN tickets t ON t.incident_id = i.id
        {where}
        GROUP BY i.id
        ORDER BY COALESCE(i.updated_at, i.last_seen, i.created_at) DESC
        LIMIT :limit
    """), params)).mappings().all()
    items = []
    seen_source_hashes = set()
    for row in rows:
        if row.get("source") == "splunk" and str(row.get("title") or "").strip() in {"", "-", "_"}:
            continue
        source_hash = row.get("source_hash")
        if row.get("source") == "splunk" and source_hash:
            if source_hash in seen_source_hashes:
                continue
            seen_source_hashes.add(source_hash)
        items.append(_api_incident(row))
    return {"incidents": items, "count": len(items), "error": None}


@api_router.post("")
async def api_create_incident(
    body: IncidentCreateIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    severity = _severity_to_int(body.severity)
    detection_source = _detection_source_value(body.detection_source)
    category = _category_value(body.category) or "other"
    status = _status_value(body.status or "pending_evidence")
    if detection_source == "splunk_alert" and status == "pending_evidence":
        status = "pending_approval"
    approval_status = "pending" if status == "pending_approval" else "approved"
    activation_state = "pending_approval" if status == "pending_approval" else "pending_evidence"
    source = body.source or ("splunk" if detection_source.startswith("splunk") else "analyst")
    source_hash = body.source_hash
    if not source_hash and (body.source_ref or body.linked_splunk_alert_id or body.linked_splunk_report_id):
        source_hash = hashlib.sha256(
            f"{source}:{body.source_ref or body.linked_splunk_alert_id or body.linked_splunk_report_id}".encode("utf-8")
        ).hexdigest()

    if source_hash:
        existing = (await db.execute(text("""
            SELECT i.*, COALESCE(i.evidence_count, COUNT(e.id)) AS evidence_count
            FROM incidents i
            LEFT JOIN evidence e ON e.incident_id = i.id
            WHERE i.source_hash = :source_hash
            GROUP BY i.id
        """), {"source_hash": source_hash})).mappings().first()
        if existing:
            return {"success": True, "incident": _api_incident(existing), "error": None, "deduplicated": True}
    mapping = auto_map_mitre(body.title, body.description, body.category, body.notes)

    stmt = text("""
        INSERT INTO incidents (
            title, description, severity, status, activation_state, is_active,
            evidence_count, category, source, owner,
            linked_splunk_alert_id, linked_splunk_report_id, detection_source,
            entities, tags, notes, approval_status, approved_by, approved_at,
            source_ref, source_hash, dedup_key, source_systems, analyst_notes,
            analyst_verdict, mitre_tactic, mitre_technique, mitre_technique_id,
            mitre_technique_name, mitre_confidence, mitre_mapping_source,
            first_seen, last_seen, updated_at
        )
        VALUES (
            :title, :description, :severity, :status, :activation_state, FALSE,
            0, :category, :source, :owner,
            :linked_splunk_alert_id, :linked_splunk_report_id, :detection_source,
            :entities, :tags, :notes, :approval_status, :approved_by, :approved_at,
            :source_ref, :source_hash, :dedup_key, :source_systems, :analyst_notes,
            'undecided', :mitre_tactic, :mitre_technique_id, :mitre_technique_id,
            :mitre_technique_name, :mitre_confidence, :mitre_mapping_source,
            NOW(), NOW(), NOW()
        )
        RETURNING *
    """).bindparams(
        bindparam("entities", type_=JSONB),
        bindparam("tags", type_=ARRAY(Text)),
        bindparam("source_systems", type_=ARRAY(Text)),
    )
    res = await db.execute(stmt, {
        "title": body.title.strip(),
        "description": body.description,
        "severity": severity,
        "status": status,
        "activation_state": activation_state,
        "category": category,
        "source": source,
        "owner": body.owner,
        "linked_splunk_alert_id": body.linked_splunk_alert_id,
        "linked_splunk_report_id": body.linked_splunk_report_id,
        "detection_source": detection_source,
        "entities": body.entities or {},
        "tags": [str(tag).strip() for tag in body.tags if str(tag).strip()][:20],
        "notes": body.notes,
        "approval_status": approval_status,
        "approved_by": user.get("username") if approval_status == "approved" else None,
        "approved_at": datetime.now(timezone.utc) if approval_status == "approved" else None,
        "source_ref": body.source_ref,
        "source_hash": source_hash,
        "dedup_key": source_hash,
        "source_systems": [source],
        "analyst_notes": body.notes or body.description,
        **mapping,
    })
    row = res.mappings().first()
    added = await _insert_evidence(db, str(row["id"]), body.evidence, user) if body.evidence else 0
    if added:
        row = (await db.execute(text("""
            SELECT i.*, COALESCE(i.evidence_count, COUNT(e.id)) AS evidence_count
            FROM incidents i
            LEFT JOIN evidence e ON e.incident_id = i.id
            WHERE i.id = :id
            GROUP BY i.id
        """), {"id": str(row["id"])})).mappings().first()
    await db.commit()
    data = _api_incident(row)
    data["evidence_added"] = added
    return {"incident": data, "success": True, "error": None}


def _alert_hash(alert: dict) -> str:
    if alert.get("source_hash"):
        return str(alert["source_hash"])
    bucket = ""
    try:
        dt = datetime.fromisoformat(str(alert.get("trigger_time") or "").replace("Z", "+00:00"))
        bucket = dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        bucket = str(alert.get("trigger_time") or "")[:10]
    seed = {
        "name": alert.get("name"),
        "search_name": alert.get("saved_search_name") or alert.get("search_name"),
        "bucket": bucket,
        "source": alert.get("source") or "splunk",
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _alert_dedup_key(alert: dict) -> str:
    seed = {
        "name": alert.get("name"),
        "search_name": alert.get("saved_search_name") or alert.get("search_name"),
        "source": alert.get("source") or "splunk",
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True, default=str).encode("utf-8")).hexdigest()


async def _upsert_external_alert(
    db: AsyncSession,
    alert: dict,
    dedupe_key: str,
    linked_incident_id: Optional[str] = None,
) -> dict:
    source_event_id = str(alert.get("source_event_id") or alert.get("source_ref") or alert.get("id") or "")[:255] or None
    rule_name = (
        _clean_alert_label(alert.get("rule_name"))
        or _clean_alert_label(alert.get("name"))
        or _clean_alert_label(alert.get("saved_search_name"))
        or _clean_alert_label(alert.get("search_name"))
        or "Splunk fired alert"
    )
    existing = (await db.execute(text("""
        SELECT * FROM external_alerts
        WHERE dedupe_key = :dedupe_key
        LIMIT 1
    """), {"dedupe_key": dedupe_key})).mappings().first()
    if existing:
        if linked_incident_id and not existing.get("linked_incident_id"):
            existing = (await db.execute(text("""
                UPDATE external_alerts
                SET linked_incident_id = :incident_id
                WHERE id = :id
                RETURNING *
            """), {"id": str(existing["id"]), "incident_id": linked_incident_id})).mappings().first()
        return dict(existing) | {"deduplicated": True}
    row = (await db.execute(text("""
        INSERT INTO external_alerts (
            source_system, source_event_id, rule_name, severity, raw_json,
            dedupe_key, linked_incident_id
        )
        VALUES (
            'splunk', :source_event_id, :rule_name, :severity, :raw_json,
            :dedupe_key, :linked_incident_id
        )
        RETURNING *
    """).bindparams(bindparam("raw_json", type_=JSONB)), {
        "source_event_id": source_event_id,
        "rule_name": rule_name[:500],
        "severity": str(alert.get("severity") or "medium")[:40],
        "raw_json": alert,
        "dedupe_key": dedupe_key,
        "linked_incident_id": linked_incident_id,
    })).mappings().first()
    return dict(row) | {"deduplicated": False}


def _clean_alert_label(value: Optional[str]) -> str:
    return SplunkAdapter._clean_saved_search_label(value or "")


def _alert_time_window(trigger_time: Optional[str]) -> tuple[str, str]:
    if not trigger_time:
        return "-24h", "now"
    try:
        dt = datetime.fromisoformat(str(trigger_time).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        earliest = (dt - timedelta(minutes=15)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        latest = (dt + timedelta(minutes=10)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return earliest, latest
    except Exception:
        return "-24h", "now"


def _query_for_triggered_alert(alert: dict, limit: int = 100) -> str:
    search = alert.get("search") or "index=*"
    query = ensure_search_prefix(search)
    earliest, latest = _alert_time_window(alert.get("trigger_time"))
    base, sep, rest = query.partition("|")
    lower = base.lower()
    if "earliest=" not in lower:
        base = f"{base.strip()} earliest={earliest}"
    if "latest=" not in lower:
        base = f"{base.strip()} latest={latest}"
    query = f"{base} |{rest}" if sep else base
    if "| head" not in query.lower():
        query = f"{query.strip()} | head {limit}"
    return query


async def _fetch_triggering_events(adapter: SplunkAdapter, alert: dict, limit: int = 100) -> tuple[list[dict], str, Optional[str]]:
    query = _query_for_triggered_alert(alert, limit=limit)
    result = await asyncio.to_thread(adapter.export_search, query)
    events = result.get("events") if isinstance(result, dict) and isinstance(result.get("events"), list) else []
    error = result.get("error") if isinstance(result, dict) else "Splunk search failed"
    return events, query, error


def _event_entities(events: list[dict]) -> dict:
    buckets = {
        "users": set(),
        "hosts": set(),
        "source_ips": set(),
        "destination_ips": set(),
        "actions": set(),
    }
    for event in events:
        for key, aliases in {
            "users": ("user", "username", "user_email", "src_user"),
            "hosts": ("host", "hostname", "dest_host", "src_host"),
            "source_ips": ("source_ip", "src_ip", "src", "client_ip"),
            "destination_ips": ("destination_ip", "dest_ip", "dest", "server_ip"),
            "actions": ("action", "event_action"),
        }.items():
            for alias in aliases:
                value = event.get(alias)
                if value:
                    buckets[key].add(str(value)[:255])
    return {key: sorted(values)[:20] for key, values in buckets.items() if values}


def _auto_incident_description(title: str, alert: dict, trigger_events: list[dict], trigger_query: str, trigger_error: Optional[str]) -> str:
    entities = _event_entities(trigger_events)
    entity_parts = []
    for label, values in entities.items():
        if values:
            entity_parts.append(f"{label.replace('_', ' ')}: {', '.join(values[:5])}")
    context = "; ".join(entity_parts) if entity_parts else "no key entities extracted yet"
    count = alert.get("result_count") or len(trigger_events)
    err = f" Log chain collection warning: {trigger_error}." if trigger_error else ""
    return (
        f"Splunk fired alert '{title}' triggered at {alert.get('trigger_time') or 'unknown time'} "
        f"with {count or 0} result(s). Auto-attached {len(trigger_events)} related event(s) "
        f"from the trigger window. Affected context: {context}. "
        f"Search context: {trigger_query or alert.get('search') or 'not available'}.{err}"
    )


def _match_triggered_alert(alerts: list[dict], key: str, incident: Optional[dict] = None) -> Optional[dict]:
    candidates = {str(key)}
    if incident:
        for field in ("source_hash", "source_ref", "linked_splunk_alert_id"):
            value = incident.get(field)
            if value:
                candidates.add(str(value))
    for alert in alerts:
        values = {
            str(alert.get("id") or ""),
            str(alert.get("source_ref") or ""),
            str(alert.get("source_hash") or ""),
            str(alert.get("saved_search_name") or ""),
            str(alert.get("search_name") or ""),
            _alert_hash(alert),
        }
        if candidates & values:
            return alert
    return None


@api_router.post("/sync-splunk-alerts")
async def api_sync_splunk_alert_candidates(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    adapter = SplunkAdapter()
    try:
        data = await asyncio.to_thread(adapter.list_fired_alerts)
    except Exception as e:
        return {"success": False, "created": 0, "candidates": [], "error": str(e) or e.__class__.__name__}

    alerts = data.get("items", []) if isinstance(data, dict) else []
    created = []
    updated = []
    stmt = text("""
        INSERT INTO incidents (
            title, description, severity, status, activation_state, is_active,
            evidence_count, category, source, linked_splunk_alert_id,
            detection_source, entities, tags, notes, approval_status,
            source_ref, source_hash, dedup_key, occurrence_count, source_systems, analyst_notes,
            mitre_tactic, mitre_technique, mitre_technique_id,
            mitre_technique_name, mitre_confidence, mitre_mapping_source,
            first_seen, last_seen, updated_at
        )
        VALUES (
            :title, :description, :severity, 'pending_approval', 'pending_approval', FALSE,
            0, :category, 'splunk', :linked_splunk_alert_id,
            'splunk_alert', :entities, :tags, :notes, 'pending',
            :source_ref, :source_hash, :dedup_key, 1, :source_systems, :analyst_notes,
            :mitre_tactic, :mitre_technique_id, :mitre_technique_id,
            :mitre_technique_name, :mitre_confidence, :mitre_mapping_source,
            NOW(), NOW(), NOW()
        )
        RETURNING *
    """).bindparams(
        bindparam("entities", type_=JSONB),
        bindparam("tags", type_=ARRAY(Text)),
        bindparam("source_systems", type_=ARRAY(Text)),
    )
    for alert in alerts[:50]:
        if not isinstance(alert, dict):
            continue
        source_hash = _alert_hash(alert)
        dedup_key = _alert_dedup_key(alert)
        source_ref = alert.get("source_ref") or alert.get("id") or alert.get("saved_search_name") or alert.get("search_name")
        existing = (await db.execute(text("""
            SELECT *
            FROM incidents
            WHERE (
                source_hash = :source_hash
                OR dedup_key = :dedup_key
                OR source_ref = :source_ref
                OR linked_splunk_alert_id = :linked_splunk_alert_id
            )
            AND last_seen >= NOW() - INTERVAL '24 hours'
            ORDER BY last_seen DESC
            LIMIT 1
        """), {
            "source_hash": source_hash,
            "dedup_key": dedup_key,
            "source_ref": source_ref,
            "linked_splunk_alert_id": alert.get("id") or alert.get("saved_search_name") or alert.get("search_name"),
        })).mappings().first()
        trigger_events, trigger_query, trigger_error = await _fetch_triggering_events(adapter, alert)
        if existing:
            await _upsert_external_alert(db, alert, dedup_key, str(existing["id"]))
            await db.execute(text("""
                UPDATE incidents
                SET updated_at = NOW(),
                    last_seen = NOW(),
                    occurrence_count = COALESCE(occurrence_count, 1) + 1,
                    analyst_notes = COALESCE(NULLIF(analyst_notes, ''), :query)
                WHERE id = :id
            """), {"id": str(existing["id"]), "query": trigger_query})
            added = await _insert_evidence(db, str(existing["id"]), trigger_events, user) if trigger_events else 0
            item = _api_incident(dict(existing) | {
                "occurrence_count": int(existing.get("occurrence_count") or 1) + 1,
                "evidence_count": int(existing.get("evidence_count") or 0) + added,
            })
            item["evidence_added"] = added
            item["trigger_error"] = trigger_error
            updated.append(item)
            continue
        severity = _severity_to_int(alert.get("severity") or "medium") if str(alert.get("severity") or "").lower() in SEVERITY_TO_INT else 3
        title = (
            _clean_alert_label(alert.get("name"))
            or _clean_alert_label(alert.get("saved_search_name"))
            or _clean_alert_label(alert.get("search_name"))
            or "Splunk fired alert"
        )
        mapping = auto_map_mitre(title, _clean_alert_label(alert.get("saved_search_name")), alert.get("search"), *(event.get("message") for event in trigger_events[:20]))
        entities = {
            "saved_search_name": _clean_alert_label(alert.get("saved_search_name") or alert.get("search_name")),
            "trigger_time": alert.get("trigger_time"),
            "result_count": alert.get("result_count") or 0,
            "trigger_condition": alert.get("trigger_condition") or "",
            "query": trigger_query or alert.get("search") or "",
            "trigger_error": trigger_error,
            "affected_entities": _event_entities(trigger_events),
        }
        row = (await db.execute(stmt, {
            "title": title,
            "description": _auto_incident_description(title, alert, trigger_events, trigger_query, trigger_error),
            "severity": severity,
            "category": "other",
            "linked_splunk_alert_id": alert.get("id") or alert.get("saved_search_name") or alert.get("search_name"),
            "entities": entities,
            "tags": ["splunk-alert", "candidate"],
            "notes": "Auto-created pending approval candidate from Splunk fired alert.",
            "source_ref": source_ref,
            "source_hash": source_hash,
            "dedup_key": dedup_key,
            "source_systems": ["splunk"],
            "analyst_notes": trigger_query or alert.get("search") or "",
            **mapping,
        })).mappings().first()
        if row:
            external_alert = await _upsert_external_alert(db, alert, dedup_key, str(row["id"]))
            added = await _insert_evidence(db, str(row["id"]), trigger_events, user) if trigger_events else 0
            item = _api_incident(dict(row) | {"evidence_count": added})
            item["external_alert_id"] = str(external_alert["id"]) if external_alert.get("id") else None
            item["evidence_added"] = added
            item["trigger_error"] = trigger_error
            created.append(item)
            await _record_outbox(db, "alert.ingested", "external_alert", str(external_alert["id"]), {"incident_id": str(row["id"])})
    if created or updated:
        await db.commit()
    return {
        "success": True,
        "created": len(created),
        "updated": len(updated),
        "candidates": created + updated,
        "error": data.get("error") if isinstance(data, dict) else None,
    }


@api_router.get("/triggered-alerts/{alert_id}")
async def api_triggered_alert_detail(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    incident = None
    try:
        incident = (await db.execute(text("SELECT * FROM incidents WHERE id = :id"), {"id": alert_id})).mappings().first()
    except Exception:
        incident = None

    adapter = SplunkAdapter()
    try:
        data = await asyncio.to_thread(adapter.list_fired_alerts)
    except Exception as e:
        return {"alert": None, "triggeringEvents": [], "count": 0, "query": "", "error": str(e) or e.__class__.__name__}

    alerts = data.get("items", []) if isinstance(data, dict) else []
    alert = _match_triggered_alert(alerts, alert_id, dict(incident) if incident else None)
    if incident and not (incident.get("source") == "splunk" or incident.get("detection_source") == "splunk_alert"):
        return {
            "alert": None,
            "triggeringEvents": [],
            "count": 0,
            "query": "",
            "error": "Incident is not linked to a triggered Splunk alert",
        }
    if not alert and incident:
        entities = incident.get("entities") or {}
        alert = {
            "id": incident.get("linked_splunk_alert_id") or incident.get("source_ref") or str(incident.get("id")),
            "name": incident.get("title"),
            "severity": INT_TO_SEVERITY.get(int(incident.get("severity") or 3), "medium"),
            "trigger_time": entities.get("trigger_time") or (incident.get("created_at").isoformat() if incident.get("created_at") else ""),
            "saved_search_name": _clean_alert_label(entities.get("saved_search_name") or incident.get("linked_splunk_alert_id")),
            "search": entities.get("query") or incident.get("analyst_notes") or "",
            "trigger_condition": entities.get("trigger_condition") or "",
            "result_count": entities.get("result_count") or 0,
            "source": "splunk",
            "status": incident.get("status") or "pending_approval",
            "source_ref": incident.get("source_ref"),
            "source_hash": incident.get("source_hash"),
        }

    if not alert:
        return {
            "alert": None,
            "triggeringEvents": [],
            "count": 0,
            "query": "",
            "error": data.get("error") or "Triggered alert was not found in Splunk",
        }

    query = _query_for_triggered_alert(alert)
    result = await asyncio.to_thread(adapter.export_search, query)
    events = result.get("events") if isinstance(result, dict) and isinstance(result.get("events"), list) else []
    return {
        "alert": alert,
        "triggeringEvents": events,
        "count": len(events),
        "query": query,
        "error": result.get("error") if isinstance(result, dict) else None,
    }


@api_router.get("/{incident_id}")
async def api_get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    row = (await db.execute(text("""
        SELECT i.*,
               COUNT(DISTINCT e.id) AS evidence_count,
               COUNT(DISTINCT a.id) + COUNT(DISTINCT ea.id) AS related_alert_count,
               COUNT(DISTINCT t.id) AS related_ticket_count
        FROM incidents i
        LEFT JOIN evidence e ON e.incident_id = i.id
        LEFT JOIN alerts a ON a.incident_id = i.id
        LEFT JOIN external_alerts ea ON ea.linked_incident_id = i.id
        LEFT JOIN tickets t ON t.incident_id = i.id
        WHERE i.id = :id
        GROUP BY i.id
    """), {"id": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = (await db.execute(text("""
        SELECT * FROM evidence WHERE incident_id = :id ORDER BY event_time ASC NULLS LAST, collected_at ASC
    """), {"id": str(incident_id)})).mappings().all()
    containment = (await db.execute(text("""
        SELECT * FROM containment_actions
        WHERE incident_id = :id
        ORDER BY requested_at DESC
        LIMIT 100
    """), {"id": str(incident_id)})).mappings().all()
    tickets = (await db.execute(text("""
        SELECT * FROM tickets
        WHERE incident_id = :id
        ORDER BY updated_at DESC
        LIMIT 100
    """), {"id": str(incident_id)})).mappings().all()
    comments = (await db.execute(text("""
        SELECT * FROM incident_comments
        WHERE incident_id = :id
        ORDER BY created_at DESC
        LIMIT 100
    """), {"id": str(incident_id)})).mappings().all()
    activity = (await db.execute(text("""
        SELECT * FROM incident_activity
        WHERE incident_id = :id
        ORDER BY created_at DESC
        LIMIT 150
    """), {"id": str(incident_id)})).mappings().all()
    external_alerts = (await db.execute(text("""
        SELECT * FROM external_alerts
        WHERE linked_incident_id = :id
        ORDER BY ingested_at DESC
        LIMIT 100
    """), {"id": str(incident_id)})).mappings().all()
    observable_rows = (await db.execute(text("""
        SELECT * FROM observables
        WHERE incident_id = :id
        ORDER BY type ASC, value ASC
    """), {"id": str(incident_id)})).mappings().all()
    mitre_links = (await db.execute(text("""
        SELECT * FROM incident_mitre_links
        WHERE incident_id = :id
        ORDER BY created_at DESC
    """), {"id": str(incident_id)})).mappings().all()
    data = _api_incident(row)
    data["evidence"] = [_evidence_to_dict(e) | {
        "event_hash": e.get("event_hash"),
        "event_time": e["event_time"].isoformat() if e.get("event_time") else None,
        "added_at": e["collected_at"].isoformat() if e.get("collected_at") else None,
        "source": e.get("source"),
        "index": e.get("index"),
        "sourcetype": e.get("sourcetype"),
        "host": e.get("host"),
        "source_ip": e.get("source_ip"),
        "destination_ip": e.get("destination_ip"),
        "user_email": e.get("user_email"),
        "action": e.get("action"),
        "category": (e.get("raw_event") or {}).get("category") or (e.get("raw_event") or {}).get("event_category"),
        "severity": (e.get("raw_event") or {}).get("severity") or (e.get("raw_event") or {}).get("level"),
        "message": e.get("message"),
        "raw_event": e.get("raw_event"),
    } for e in evidence]
    data["containment_actions"] = [{
        "id": str(a["id"]),
        "incident_id": str(a["incident_id"]) if a.get("incident_id") else None,
        "ticket_id": str(a["ticket_id"]) if a.get("ticket_id") else None,
        "action_type": a.get("action_type"),
        "target_ip": a.get("target_ip"),
        "firewall": a.get("firewall"),
        "alias_name": a.get("alias_name"),
        "reason": a.get("reason"),
        "requested_by": a.get("requested_by"),
        "requested_at": a["requested_at"].isoformat() if a.get("requested_at") else None,
        "executed_at": a["executed_at"].isoformat() if a.get("executed_at") else None,
        "status": a.get("status"),
        "result_message": a.get("result_message"),
        "raw_response": a.get("raw_response"),
    } for a in containment]
    data["tickets"] = [{
        "id": str(t["id"]),
        "ticket_number": t.get("ticket_number"),
        "incident_id": str(t["incident_id"]) if t.get("incident_id") else None,
        "title": t.get("title"),
        "description": t.get("description") or "",
        "queue": t.get("queue") or "",
        "assignee": t.get("assignee") or "",
        "priority": t.get("priority") or "medium",
        "status": t.get("status") or "open",
        "sla_due_at": t["sla_due_at"].isoformat() if t.get("sla_due_at") else None,
        "escalation_level": int(t.get("escalation_level") or 0),
        "requested_action": t.get("requested_action") or "",
        "resolution_notes": t.get("resolution_notes") or "",
        "created_by": t.get("created_by") or "",
        "created_at": t["created_at"].isoformat() if t.get("created_at") else None,
        "updated_at": t["updated_at"].isoformat() if t.get("updated_at") else None,
        "closed_at": t["closed_at"].isoformat() if t.get("closed_at") else None,
    } for t in tickets]
    data["external_alerts"] = [{
        "id": str(a["id"]),
        "source_system": a.get("source_system"),
        "source_event_id": a.get("source_event_id"),
        "rule_name": a.get("rule_name"),
        "severity": a.get("severity"),
        "dedupe_key": a.get("dedupe_key"),
        "ingested_at": a["ingested_at"].isoformat() if a.get("ingested_at") else None,
        "raw_json": a.get("raw_json"),
    } for a in external_alerts]
    data["mitre_links"] = [{
        "id": str(m["id"]),
        "incident_id": str(m["incident_id"]),
        "tactic_id": m.get("tactic_id"),
        "technique_id": m.get("technique_id"),
        "technique_name": m.get("technique_name"),
        "confidence": float(m.get("confidence")) if m.get("confidence") is not None else None,
        "mapped_by": m.get("mapped_by"),
        "mapping_source": m.get("mapping_source") or "manual",
        "created_at": m["created_at"].isoformat() if m.get("created_at") else None,
    } for m in mitre_links]
    data["workflow"] = {
        "queue": data.get("queue") or "SOC",
        "assignee": data.get("owner") or "",
        "priority": data.get("priority") or data.get("severity") or "medium",
        "workflow_status": data.get("workflow_status") or "open",
        "sla_due_at": data.get("sla_due_at"),
        "first_ack_due_at": data.get("first_ack_due_at"),
        "resolve_due_at": data.get("resolve_due_at"),
        "sla_state": data.get("sla_state"),
        "escalation_level": data.get("escalation_level") or 0,
        "requested_action": data.get("requested_action") or "",
        "resolution_notes": data.get("resolution_notes") or "",
        "close_reason": data.get("close_reason") or "",
    }
    data["comments"] = [_comment_to_dict(c) for c in comments]
    data["activity"] = [_activity_to_dict(a) for a in activity]
    stored_observables: dict[str, list[str]] = {}
    for obs in observable_rows:
        key = str(obs.get("type") or "other")
        stored_observables.setdefault(key, []).append(obs.get("value"))
    data["observables"] = {
        "users": sorted(set(filter(None, [*stored_observables.get("user", []), data["entities"].get("user"), *[e.get("user_email") for e in data["evidence"]]]))),
        "hosts": sorted(set(filter(None, [*stored_observables.get("host", []), data["entities"].get("host"), *[e.get("host") for e in data["evidence"]]]))),
        "source_ips": sorted(set(filter(None, [data["entities"].get("source_ip"), *[e.get("source_ip") for e in data["evidence"]]]))),
        "destination_ips": sorted(set(filter(None, [data["entities"].get("destination_ip"), *[e.get("destination_ip") for e in data["evidence"]]]))),
        "ips": sorted(set(filter(None, stored_observables.get("ip", [])))),
        "urls": sorted(set(filter(None, [*stored_observables.get("url", []), data["entities"].get("url")]))),
        "domains": sorted(set(filter(None, [*stored_observables.get("domain", []), data["entities"].get("domain")]))),
        "hashes": sorted(set(filter(None, [*stored_observables.get("hash", []), data["entities"].get("hash")]))),
        "files": sorted(set(filter(None, [*stored_observables.get("file", []), data["entities"].get("file")]))),
        "items": [{
            "id": str(obs["id"]),
            "type": obs.get("type"),
            "value": obs.get("value"),
            "is_ioc": bool(obs.get("is_ioc")),
            "is_sighted": bool(obs.get("is_sighted")),
            "first_seen_at": obs["first_seen_at"].isoformat() if obs.get("first_seen_at") else None,
        } for obs in observable_rows],
    }
    data["response_actions"] = list(data["containment_actions"])
    data["related_alerts"] = list(data["external_alerts"])
    return {"success": True, "incident": data, "error": None}


@api_router.patch("/{incident_id}")
async def api_patch_incident(
    incident_id: UUID,
    body: IncidentPatchIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    updates = ["updated_at = NOW()"]
    params: dict = {"id": str(incident_id)}
    if body.title is not None:
        updates.append("title = :title")
        params["title"] = body.title.strip()
    if body.description is not None:
        updates.append("description = :description")
        updates.append("analyst_notes = :description")
        params["description"] = body.description
    if body.severity is not None:
        updates.append("severity = :severity")
        params["severity"] = _severity_to_int(body.severity)
    if body.status is not None:
        updates.append("status = :status")
        params["status"] = _status_value(body.status)
    if body.category is not None:
        updates.append("category = :category")
        params["category"] = _category_value(body.category)
    if body.owner is not None:
        updates.append("owner = :owner")
        params["owner"] = body.owner
    if body.tags is not None:
        updates.append("tags = :tags")
        params["tags"] = body.tags
    if body.entities is not None:
        updates.append("entities = :entities")
        params["entities"] = body.entities
    if body.detection_source is not None:
        updates.append("detection_source = :detection_source")
        params["detection_source"] = _detection_source_value(body.detection_source)
    if body.notes is not None:
        updates.append("notes = :notes")
        params["notes"] = body.notes
    if body.analyst_verdict is not None:
        verdict = str(body.analyst_verdict).strip().lower().replace(" ", "_").replace("-", "_")
        if verdict not in VERDICTS:
            raise HTTPException(status_code=400, detail="Invalid analyst verdict")
        reason = body.verdict_reason or ""
        if verdict == "false_positive" and not reason.strip():
            raise HTTPException(status_code=400, detail="False Positive verdict requires a reason")
        updates.extend([
            "analyst_verdict = :analyst_verdict",
            "verdict_reason = :verdict_reason",
            "verdict_by = :verdict_by",
            "verdict_at = NOW()",
        ])
        params["analyst_verdict"] = verdict
        params["verdict_reason"] = reason
        if verdict == "duplicate" and body.duplicate_of:
            params["verdict_reason"] = f"{reason}\nDuplicate of: {body.duplicate_of}".strip()
        params["verdict_by"] = user.get("username")
        if verdict == "false_positive":
            updates.append("is_false_positive = TRUE")
        elif verdict in {"true_positive", "benign_positive", "needs_more_evidence"}:
            updates.append("is_false_positive = FALSE")
    if body.mitre_tactic is not None:
        updates.append("mitre_tactic = :mitre_tactic")
        params["mitre_tactic"] = body.mitre_tactic
    if body.mitre_technique_id is not None:
        updates.append("mitre_technique_id = :mitre_technique_id")
        updates.append("mitre_technique = :mitre_technique_id")
        params["mitre_technique_id"] = body.mitre_technique_id
    if body.mitre_technique_name is not None:
        updates.append("mitre_technique_name = :mitre_technique_name")
        params["mitre_technique_name"] = body.mitre_technique_name
    if body.mitre_confidence is not None:
        updates.append("mitre_confidence = :mitre_confidence")
        params["mitre_confidence"] = max(0.0, min(float(body.mitre_confidence), 1.0))
    if body.mitre_mapping_source is not None:
        updates.append("mitre_mapping_source = :mitre_mapping_source")
        params["mitre_mapping_source"] = str(body.mitre_mapping_source or "manual")[:50]
    if body.approval_status is not None:
        _require_admin(user)
        approval = str(body.approval_status).strip().lower()
        if approval not in {"pending", "approved", "rejected"}:
            raise HTTPException(status_code=400, detail="Invalid approval status")
        updates.append("approval_status = :approval_status")
        params["approval_status"] = approval
        if approval == "approved":
            updates.extend(["approved_by = :approved_by", "approved_at = :approved_at"])
            params["approved_by"] = user.get("username")
            params["approved_at"] = datetime.now(timezone.utc)
            updates.append("status = CASE WHEN status = 'pending_approval' THEN 'pending_evidence' ELSE status END")
            updates.append("activation_state = CASE WHEN evidence_count > 0 THEN 'active' ELSE 'pending_evidence' END")
            updates.append("is_active = evidence_count > 0")
        if approval == "rejected":
            updates.append("status = 'rejected'")
            updates.append("activation_state = 'rejected'")
    stmt = text(f"UPDATE incidents SET {', '.join(updates)} WHERE id = :id RETURNING *")
    typed_params = []
    if "tags" in params:
        typed_params.append(bindparam("tags", type_=ARRAY(Text)))
    if "entities" in params:
        typed_params.append(bindparam("entities", type_=JSONB))
    if typed_params:
        stmt = stmt.bindparams(*typed_params)
    res = await db.execute(stmt, params)
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    await db.commit()
    patched = dict(row)
    patched.setdefault("evidence_count", 0)
    await _record_activity(db, str(incident_id), "incident_updated", "Incident fields updated", user)
    await db.commit()
    return {"incident": _api_incident(patched), "error": None}


@api_router.get("/{incident_id}/workflow")
async def api_get_incident_workflow(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    row = (await db.execute(text("SELECT * FROM incidents WHERE id = :id"), {"id": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = _api_incident(row)
    return {
        "success": True,
        "workflow": {
            "queue": data.get("queue"),
            "assignee": data.get("owner") or "",
            "priority": data.get("priority"),
            "workflow_status": data.get("workflow_status"),
            "sla_due_at": data.get("sla_due_at"),
            "first_ack_due_at": data.get("first_ack_due_at"),
            "resolve_due_at": data.get("resolve_due_at"),
            "sla_state": data.get("sla_state"),
            "escalation_level": data.get("escalation_level"),
            "requested_action": data.get("requested_action"),
            "resolution_notes": data.get("resolution_notes"),
            "close_reason": data.get("close_reason"),
        },
        "error": None,
    }


@api_router.patch("/{incident_id}/workflow")
async def api_patch_incident_workflow(
    incident_id: UUID,
    body: IncidentWorkflowPatchIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    updates = ["updated_at = NOW()"]
    params: dict = {"id": str(incident_id)}
    if body.queue is not None:
        updates.append("queue = :queue")
        params["queue"] = body.queue.strip() or "SOC"
    if body.owner is not None:
        updates.append("owner = :owner")
        params["owner"] = body.owner.strip()
    if body.priority is not None:
        priority = _clean_token(body.priority, "medium")
        if priority not in WORKFLOW_PRIORITIES:
            raise HTTPException(status_code=400, detail="Invalid workflow priority")
        updates.append("priority = :priority")
        params["priority"] = priority
    if body.workflow_status is not None:
        workflow_status = _clean_token(body.workflow_status, "open")
        if workflow_status not in WORKFLOW_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid workflow status")
        updates.append("workflow_status = :workflow_status")
        params["workflow_status"] = workflow_status
        if workflow_status in {"closed", "cancelled"}:
            updates.append("closed_at = COALESCE(closed_at, NOW())")
    for field in ("sla_due_at", "first_ack_due_at", "resolve_due_at"):
        value = getattr(body, field)
        if value is not None:
            updates.append(f"{field} = :{field}")
            params[field] = _parse_datetime(value)
    if body.escalation_level is not None:
        updates.append("escalation_level = :escalation_level")
        params["escalation_level"] = body.escalation_level
    for field in ("requested_action", "resolution_notes", "close_reason"):
        value = getattr(body, field)
        if value is not None:
            updates.append(f"{field} = :{field}")
            params[field] = value

    row = (await db.execute(text(f"""
        UPDATE incidents
        SET {', '.join(updates)}
        WHERE id = :id
        RETURNING *
    """), params)).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    await _record_activity(db, str(incident_id), "workflow_updated", "Incident workflow fields updated", user, body.model_dump(exclude_none=True))
    await db.commit()
    data = _api_incident(row)
    return {"success": True, "workflow": data, "incident": data, "error": None}


@api_router.get("/{incident_id}/comments")
async def api_get_incident_comments(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    rows = (await db.execute(text("""
        SELECT * FROM incident_comments
        WHERE incident_id = :incident_id
        ORDER BY created_at DESC
        LIMIT 100
    """), {"incident_id": str(incident_id)})).mappings().all()
    return {"success": True, "comments": [_comment_to_dict(row) for row in rows], "count": len(rows), "error": None}


@api_router.post("/{incident_id}/comments")
async def api_add_incident_comment(
    incident_id: UUID,
    body: IncidentCommentIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    exists = (await db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": str(incident_id)})).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    row = (await db.execute(text("""
        INSERT INTO incident_comments (incident_id, body, comment_type, created_by)
        VALUES (:incident_id, :body, :comment_type, :created_by)
        RETURNING *
    """), {
        "incident_id": str(incident_id),
        "body": body.body.strip(),
        "comment_type": _clean_token(body.comment_type, "internal_note")[:50],
        "created_by": user.get("username"),
    })).mappings().first()
    await _record_activity(db, str(incident_id), "comment_added", "Analyst comment added", user, {"comment_id": str(row["id"])})
    await db.commit()
    return {"success": True, "comment": _comment_to_dict(row), "error": None}


@api_router.get("/{incident_id}/activity")
async def api_get_incident_activity(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    rows = (await db.execute(text("""
        SELECT * FROM incident_activity
        WHERE incident_id = :incident_id
        ORDER BY created_at DESC
        LIMIT 150
    """), {"incident_id": str(incident_id)})).mappings().all()
    return {"success": True, "activity": [_activity_to_dict(row) for row in rows], "count": len(rows), "error": None}


def _observable_to_dict(row) -> dict:
    return {
        "id": str(row["id"]),
        "incident_id": str(row["incident_id"]),
        "type": row.get("type"),
        "value": row.get("value"),
        "is_ioc": bool(row.get("is_ioc")),
        "is_sighted": bool(row.get("is_sighted")),
        "first_seen_at": row["first_seen_at"].isoformat() if row.get("first_seen_at") else None,
    }


@api_router.get("/{incident_id}/observables")
async def api_get_observables(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    rows = (await db.execute(text("""
        SELECT * FROM observables
        WHERE incident_id = :incident_id
        ORDER BY type ASC, value ASC
    """), {"incident_id": str(incident_id)})).mappings().all()
    return {"success": True, "observables": [_observable_to_dict(row) for row in rows], "count": len(rows), "error": None}


@api_router.post("/{incident_id}/observables")
async def api_add_observable(
    incident_id: UUID,
    body: ObservableIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    exists = (await db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": str(incident_id)})).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    obs_type = _clean_token(body.type, "other")[:50]
    value = body.value.strip()
    params = {
        "incident_id": str(incident_id),
        "type": obs_type,
        "value": value,
        "is_ioc": body.is_ioc,
        "is_sighted": body.is_sighted,
    }
    existing = (await db.execute(text("""
        SELECT id FROM observables
        WHERE incident_id = :incident_id AND type = :type AND lower(value) = lower(:value)
        LIMIT 1
    """), params)).scalar()
    if existing:
        row = (await db.execute(text("""
            UPDATE observables
            SET is_ioc = :is_ioc,
                is_sighted = :is_sighted
            WHERE id = :id
            RETURNING *
        """), params | {"id": str(existing)})).mappings().first()
    else:
        row = (await db.execute(text("""
            INSERT INTO observables (incident_id, type, value, is_ioc, is_sighted)
            VALUES (:incident_id, :type, :value, :is_ioc, :is_sighted)
            RETURNING *
        """), params)).mappings().first()
    await _record_activity(db, str(incident_id), "observable_added", f"Observable added: {obs_type} {value}", user)
    await _record_outbox(db, "observable.added", "incident", str(incident_id), {"type": obs_type, "value": value})
    await db.commit()
    return {"success": True, "observable": _observable_to_dict(row), "error": None}


def _mitre_link_to_dict(row) -> dict:
    confidence_score = row.get("confidence_score")
    if confidence_score is None and row.get("confidence") is not None:
        confidence_score = round(float(row.get("confidence")) * 100)
    return {
        "id": str(row["id"]),
        "incident_id": str(row["incident_id"]),
        "tactic_id": row.get("tactic_id"),
        "technique_id": row.get("technique_id"),
        "subtechnique_id": row.get("subtechnique_id"),
        "technique_name": row.get("technique_name"),
        "confidence": float(row.get("confidence")) if row.get("confidence") is not None else None,
        "confidence_score": int(confidence_score or 0),
        "mapped_by": row.get("mapped_by"),
        "mapping_source": row.get("mapping_source") or "manual",
        "reason": row.get("reason") or "",
        "matched_fields": row.get("matched_fields") or {},
        "matched_evidence_ids": row.get("matched_evidence_ids") or [],
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
    }


@api_router.get("/{incident_id}/mitre-links")
async def api_get_mitre_links(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    rows = (await db.execute(text("""
        SELECT * FROM incident_mitre_links
        WHERE incident_id = :incident_id
        ORDER BY created_at DESC
    """), {"incident_id": str(incident_id)})).mappings().all()
    return {"success": True, "mitre_links": [_mitre_link_to_dict(row) for row in rows], "count": len(rows), "error": None}


@api_router.post("/{incident_id}/mitre-links")
async def api_add_mitre_link(
    incident_id: UUID,
    body: IncidentMitreLinkIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    exists = (await db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": str(incident_id)})).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    row = (await db.execute(text("""
        INSERT INTO incident_mitre_links (
            incident_id, tactic_id, technique_id, technique_name,
            subtechnique_id, confidence, confidence_score, mapped_by, mapping_source,
            reason, matched_fields, matched_evidence_ids, created_by, updated_at
        )
        VALUES (
            :incident_id, :tactic_id, :technique_id, :technique_name,
            :subtechnique_id, :confidence, :confidence_score, :mapped_by, :mapping_source,
            :reason, :matched_fields, :matched_evidence_ids, :created_by, NOW()
        )
        ON CONFLICT (incident_id, technique_id, COALESCE(subtechnique_id, ''), COALESCE(tactic_id, '')) DO UPDATE
        SET tactic_id = EXCLUDED.tactic_id,
            subtechnique_id = EXCLUDED.subtechnique_id,
            technique_name = EXCLUDED.technique_name,
            confidence = EXCLUDED.confidence,
            confidence_score = EXCLUDED.confidence_score,
            mapped_by = EXCLUDED.mapped_by,
            mapping_source = EXCLUDED.mapping_source,
            reason = EXCLUDED.reason,
            matched_fields = EXCLUDED.matched_fields,
            matched_evidence_ids = EXCLUDED.matched_evidence_ids,
            updated_at = NOW()
        RETURNING *
    """).bindparams(
        bindparam("matched_fields", type_=JSONB),
        bindparam("matched_evidence_ids", type_=JSONB),
    ), {
        "incident_id": str(incident_id),
        "tactic_id": body.tactic_id,
        "technique_id": body.technique_id.strip(),
        "subtechnique_id": body.subtechnique_id,
        "technique_name": body.technique_name,
        "confidence": body.confidence if body.confidence is not None else (body.confidence_score / 100 if body.confidence_score is not None else 1),
        "confidence_score": body.confidence_score if body.confidence_score is not None else (round(float(body.confidence) * 100) if body.confidence is not None else 100),
        "mapped_by": user.get("username"),
        "reason": body.reason or "Analyst mapped this ATT&CK technique manually.",
        "matched_fields": body.matched_fields or {},
        "matched_evidence_ids": body.matched_evidence_ids or [],
        "created_by": user.get("username"),
        "mapping_source": _clean_token(body.mapping_source, "manual")[:50],
    })).mappings().first()
    await _record_activity(db, str(incident_id), "mitre_mapped", f"MITRE mapping added: {body.technique_id}", user)
    await _record_outbox(db, "mitre.mapping_added", "incident", str(incident_id), {"technique_id": body.technique_id})
    await db.commit()
    return {"success": True, "mitre_link": _mitre_link_to_dict(row), "error": None}


@api_router.delete("/{incident_id}/mitre-links/{link_id}")
async def api_delete_mitre_link(
    incident_id: UUID,
    link_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    row = (await db.execute(text("""
        DELETE FROM incident_mitre_links
        WHERE id = :link_id AND incident_id = :incident_id
        RETURNING *
    """), {"link_id": str(link_id), "incident_id": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="MITRE mapping not found")
    await _record_activity(db, str(incident_id), "mitre_unmapped", f"MITRE mapping removed: {row.get('technique_id')}", user)
    await db.commit()
    return {"success": True, "deletedMitreLinkId": str(link_id), "error": None}


@api_router.post("/{incident_id}/evidence")
async def api_add_evidence(
    incident_id: UUID,
    body: EvidenceIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    exists = (await db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": str(incident_id)})).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    added = await _insert_evidence(db, str(incident_id), [body.event], user)
    await db.commit()
    return {"success": True, "incidentId": str(incident_id), "added": added, "error": None}


@api_router.post("/{incident_id}/evidence/bulk")
async def api_add_evidence_bulk(
    incident_id: UUID,
    body: EvidenceBulkIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    _require_write(user)
    if not body.events:
        raise HTTPException(status_code=400, detail="No evidence events provided")
    exists = (await db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": str(incident_id)})).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    added = await _insert_evidence(db, str(incident_id), body.events, user)
    await db.commit()
    return {"success": True, "incidentId": str(incident_id), "added": added, "error": None}


@api_router.delete("/{incident_id}")
async def api_delete_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_recent_mfa),
):
    _require_admin(user)
    row = (await db.execute(text("""
        SELECT id FROM incidents WHERE id = :id
    """), {"id": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence_count = int((await db.execute(text("""
        SELECT COUNT(*) FROM evidence WHERE incident_id = :id
    """), {"id": str(incident_id)})).scalar() or 0)

    try:
        # Preserve the containment audit trail while removing the incident entity.
        await db.execute(text("""
            UPDATE containment_actions
            SET incident_id = NULL
            WHERE incident_id = :id
        """), {"id": str(incident_id)})
        await db.execute(text("""
            UPDATE tickets
            SET incident_id = NULL,
                updated_at = NOW()
            WHERE incident_id = :id
        """), {"id": str(incident_id)})
        await db.execute(text("""
            DELETE FROM incidents
            WHERE id = :id
        """), {"id": str(incident_id)})
        await db.commit()
    except Exception as e:
        await db.rollback()
        return {"success": False, "error": str(e) or e.__class__.__name__}

    return {
        "success": True,
        "deletedIncidentId": str(incident_id),
        "deletedEvidenceCount": evidence_count,
        "error": None,
    }


def _html_escape(value) -> str:
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@api_router.get("/{incident_id}/report/pdf")
async def api_incident_pdf(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewer cannot export incident reports")
    row = (await db.execute(text("""
        SELECT i.*, COUNT(e.id) AS evidence_count
        FROM incidents i
        LEFT JOIN evidence e ON e.incident_id = i.id
        WHERE i.id = :id
        GROUP BY i.id
    """), {"id": str(incident_id)})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = (await db.execute(text("""
        SELECT * FROM evidence
        WHERE incident_id = :id
        ORDER BY event_time ASC NULLS LAST, collected_at ASC
        LIMIT 50
    """), {"id": str(incident_id)})).mappings().all()
    containment = (await db.execute(text("""
        SELECT * FROM containment_actions
        WHERE incident_id = :id
        ORDER BY requested_at ASC
        LIMIT 50
    """), {"id": str(incident_id)})).mappings().all()
    mitre_links = (await db.execute(text("""
        SELECT * FROM incident_mitre_links
        WHERE incident_id = :id
        ORDER BY COALESCE(confidence_score, ROUND(COALESCE(confidence, 0) * 100)::int) DESC, created_at DESC
        LIMIT 25
    """), {"id": str(incident_id)})).mappings().all()
    incident = _api_incident(row)
    evidence_rows = "".join(
        f"<tr><td>{_html_escape(e.get('event_time') or e.get('collected_at'))}</td>"
        f"<td>{_html_escape(e.get('source_ip'))}</td>"
        f"<td>{_html_escape(e.get('destination_ip'))}</td>"
        f"<td>{_html_escape(e.get('user_email'))}</td>"
        f"<td>{_html_escape(e.get('action'))}</td>"
        f"<td>{_html_escape((e.get('message') or '')[:220])}</td></tr>"
        for e in evidence
    ) or "<tr><td colspan='6'>No evidence attached.</td></tr>"
    containment_rows = "".join(
        f"<tr><td>{_html_escape(a.get('requested_at'))}</td>"
        f"<td>{_html_escape(a.get('action_type'))}</td>"
        f"<td>{_html_escape(a.get('target_ip'))}</td>"
        f"<td>{_html_escape(a.get('requested_by'))}</td>"
        f"<td>{_html_escape(a.get('status'))}</td>"
        f"<td>{_html_escape(a.get('reason'))}</td></tr>"
        for a in containment
    ) or "<tr><td colspan='6'>No containment actions recorded.</td></tr>"
    mitre_rows = "".join(
        f"<tr><td>{_html_escape(m.get('tactic_id'))}</td>"
        f"<td>{_html_escape(m.get('subtechnique_id') or m.get('technique_id'))}</td>"
        f"<td>{_html_escape(m.get('technique_name'))}</td>"
        f"<td>{_html_escape(m.get('confidence_score') or (round(float(m.get('confidence') or 0) * 100)))}</td>"
        f"<td>{_html_escape(m.get('mapping_source') or 'manual')}</td>"
        f"<td>{_html_escape((m.get('reason') or '')[:260])}</td></tr>"
        for m in mitre_links
    ) or "<tr><td colspan='6'>No MITRE ATT&CK mappings recorded.</td></tr>"
    html = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: Helvetica, Arial, sans-serif; color: #111827; font-size: 10pt; }}
h1 {{ color: #0f172a; margin-bottom: 2px; }}
h2 {{ color: #1e3a8a; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin-top: 18px; }}
.sub {{ color: #64748b; margin-bottom: 16px; }}
.grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }}
.box {{ border: 1px solid #cbd5e1; background: #f8fafc; padding: 8px; border-radius: 4px; }}
.label {{ color: #64748b; font-size: 8pt; text-transform: uppercase; }}
.value {{ font-weight: 700; margin-top: 3px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
th, td {{ border-bottom: 1px solid #e2e8f0; padding: 5px 6px; text-align: left; vertical-align: top; }}
th {{ background: #f1f5f9; color: #334155; }}
</style>
</head>
<body>
<h1>{_html_escape(incident['title'])}</h1>
<div class="sub">ZeroTrustX Incident Report - generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
<div class="grid">
<div class="box"><div class="label">Severity</div><div class="value">{_html_escape(incident['severity'])}</div></div>
<div class="box"><div class="label">Status</div><div class="value">{_html_escape(incident['status'])}</div></div>
<div class="box"><div class="label">Verdict</div><div class="value">{_html_escape(incident['analyst_verdict'])}</div></div>
<div class="box"><div class="label">Created</div><div class="value">{_html_escape(incident['created_at'])}</div></div>
<div class="box"><div class="label">Updated</div><div class="value">{_html_escape(incident['updated_at'])}</div></div>
<div class="box"><div class="label">Evidence</div><div class="value">{_html_escape(incident['evidence_count'])}</div></div>
</div>
<h2>Executive Summary</h2>
<p>{_html_escape(incident['description'])}</p>
<h2>MITRE ATT&CK</h2>
<table><tr><th>Tactic</th><th>Technique</th><th>Name</th><th>Confidence</th><th>Source</th><th>Reason</th></tr>{mitre_rows}</table>
<h2>Affected Entities</h2>
<pre>{_html_escape(json.dumps(incident.get('entities') or {}, indent=2))}</pre>
<h2>Evidence Timeline</h2>
<table><tr><th>Time</th><th>Source IP</th><th>Destination IP</th><th>User</th><th>Action</th><th>Message</th></tr>{evidence_rows}</table>
<h2>Containment Actions</h2>
<table><tr><th>Time</th><th>Action</th><th>Target</th><th>By</th><th>Status</th><th>Reason</th></tr>{containment_rows}</table>
<h2>Analyst Notes</h2>
<p>{_html_escape(incident.get('notes') or row.get('analyst_notes'))}</p>
<h2>Recommendations</h2>
<p>Review attached evidence, confirm verdict, validate affected entities, and document containment or monitoring actions.</p>
</body>
</html>
"""
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html).write_pdf()
    except Exception as e:
        return Response(content=f"PDF generation failed: {e}".encode(), status_code=500, media_type="text/plain")
    filename = f"incident-{incident_id}.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
