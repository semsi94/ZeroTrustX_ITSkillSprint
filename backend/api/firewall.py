import ipaddress
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from adapters.pfsense_adapter import PfSenseAdapter
from api.deps import current_user, require_recent_mfa
from config import get_settings
from db.session import get_db

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


class FirewallActionIn(BaseModel):
    ip: str
    reason: str = Field("", max_length=1000)
    incident_id: Optional[UUID] = None
    alias: Optional[str] = None


class FirewallCheckIn(BaseModel):
    ip: str
    incident_id: Optional[UUID] = None
    alias: Optional[str] = None


class UnifiedFirewallActionIn(BaseModel):
    action: str = Field(..., max_length=50)
    target_ip: str
    reason: str = Field("", max_length=1000)
    incident_id: Optional[UUID] = None
    ticket_id: Optional[UUID] = None
    alias: Optional[str] = None
    notes: Optional[str] = Field(None, max_length=2000)


def _can_contain(user: dict) -> bool:
    return user.get("role") in {"admin", "senior_analyst", "soc_analyst", "analyst"}


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")


def _audit_row(row) -> dict:
    return {
        "id": str(row["id"]),
        "incident_id": str(row["incident_id"]) if row.get("incident_id") else None,
        "ticket_id": str(row["ticket_id"]) if row.get("ticket_id") else None,
        "action_type": row.get("action_type"),
        "target_ip": row.get("target_ip"),
        "target_type": row.get("target_type") or "ip",
        "target_value": row.get("target_value") or row.get("target_ip"),
        "firewall": row.get("firewall"),
        "provider": row.get("provider") or row.get("firewall") or "pfSense",
        "alias_name": row.get("alias_name"),
        "reason": row.get("reason"),
        "requested_by": row.get("requested_by"),
        "requested_at": row["requested_at"].isoformat() if row.get("requested_at") else None,
        "executed_at": row["executed_at"].isoformat() if row.get("executed_at") else None,
        "status": row.get("status"),
        "result_message": row.get("result_message"),
        "raw_response": row.get("raw_response"),
    }


async def _record_action(
    db: AsyncSession,
    *,
    body_ip: str,
    action_type: str,
    status: str,
    user: dict,
    reason: Optional[str] = None,
    incident_id: Optional[UUID] = None,
    ticket_id: Optional[UUID] = None,
    alias: Optional[str] = None,
    result_message: Optional[str] = None,
    raw_response: Optional[dict] = None,
) -> dict:
    stmt = text("""
        INSERT INTO containment_actions (
            incident_id, ticket_id, action_type, target_ip, target_type, target_value, firewall, provider, alias_name, reason,
            requested_by, executed_at, status, result_message, raw_response
        )
        VALUES (
            :incident_id, :ticket_id, :action_type, :target_ip, 'ip', :target_ip, 'pfSense', 'pfSense', :alias_name, :reason,
            :requested_by, NOW(), :status, :result_message, :raw_response
        )
        RETURNING *
    """).bindparams(bindparam("raw_response", type_=JSONB))
    row = (await db.execute(stmt, {
        "incident_id": str(incident_id) if incident_id else None,
        "ticket_id": str(ticket_id) if ticket_id else None,
        "action_type": action_type,
        "target_ip": body_ip,
        "alias_name": alias,
        "reason": reason,
        "requested_by": user.get("username"),
        "status": status,
        "result_message": result_message,
        "raw_response": raw_response or {},
    })).mappings().first()
    await db.execute(text("""
        INSERT INTO audit_log (actor_id, action, object_type, object_id, outcome)
        VALUES (:actor_id, :action, 'containment_action', :object_id, :outcome)
    """), {
        "actor_id": user.get("id") or user.get("username"),
        "action": f"firewall.{action_type}",
        "object_id": str(row["id"]),
        "outcome": "success" if status in {"success", "blocked", "not_blocked"} else status,
    })
    await db.execute(text("""
        INSERT INTO event_outbox (event_type, aggregate_type, aggregate_id, payload_json)
        VALUES (:event_type, 'containment_action', :aggregate_id, :payload)
    """).bindparams(bindparam("payload", type_=JSONB)), {
        "event_type": f"response.{action_type}",
        "aggregate_id": str(row["id"]),
        "payload": {"incident_id": str(incident_id) if incident_id else None, "ticket_id": str(ticket_id) if ticket_id else None},
    })
    await db.commit()
    return _audit_row(row)


@router.get("/status")
async def status(user: dict = Depends(current_user)):
    settings = get_settings()
    adapter = PfSenseAdapter()
    result = adapter.test_connection()
    return {
        "success": bool(result.get("success", result.get("connected"))),
        "configured": adapter.is_configured(),
        "status": result.get("status") or ("connected" if result.get("connected") else "error"),
        "message": result.get("message"),
        "error": result.get("error"),
        "alias": settings.PFSENSE_BLOCK_ALIAS,
    }


@router.get("/blocked-ips")
async def blocked_ips(user: dict = Depends(current_user)):
    adapter = PfSenseAdapter()
    if not adapter.is_configured():
        return {"success": False, "ips": [], "blocked_ips": [], "alias": adapter.default_alias, "error": "pfSense is not configured"}
    try:
        data = adapter.list_alias_ips()
        ips = data.get("ips", [])
        return {"success": True, "ips": ips, "blocked_ips": ips, "alias": data.get("alias"), "error": None}
    except Exception as e:
        return {"success": False, "ips": [], "blocked_ips": [], "alias": adapter.default_alias, "error": str(e) or e.__class__.__name__}


@router.get("/actions")
async def actions(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    rows = (await db.execute(text("""
        SELECT * FROM containment_actions
        ORDER BY requested_at DESC
        LIMIT 200
    """))).mappings().all()
    return {"actions": [_audit_row(row) for row in rows], "count": len(rows), "error": None}


@router.post("/action")
async def unified_firewall_action(
    body: UnifiedFirewallActionIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_recent_mfa),
):
    if not _can_contain(user):
        raise HTTPException(status_code=403, detail="Containment action not permitted")

    action = body.action.strip().lower()
    if action not in {"block_ip", "unblock_ip", "check_status"}:
        raise HTTPException(status_code=400, detail="Invalid firewall action")

    ip = _validate_ip(body.target_ip)
    reason = (body.reason or "").strip()
    notes = (body.notes or "").strip()
    if action in {"block_ip", "unblock_ip"} and not reason:
        raise HTTPException(status_code=400, detail="Reason is required for block and unblock actions")
    audit_reason = reason or "Status check"
    if notes:
        audit_reason = f"{audit_reason}\nNotes: {notes}"

    adapter = PfSenseAdapter()
    try:
        if action == "block_ip":
            result = adapter.add_to_alias(ip, body.alias)
            status_value = "success"
            message = result.get("message") or "IP blocked"
        elif action == "unblock_ip":
            result = adapter.remove_from_alias(ip, body.alias)
            status_value = "success"
            message = result.get("message") or "IP unblocked"
        else:
            result = adapter.check_ip(ip, body.alias)
            status_value = "blocked" if result.get("blocked") else "not_blocked"
            message = "IP is blocked" if result.get("blocked") else "IP is not blocked"

        audit = await _record_action(
            db,
            body_ip=ip,
            action_type=action,
            status="success",
            user=user,
            reason=audit_reason,
            incident_id=body.incident_id,
            ticket_id=body.ticket_id,
            alias=result.get("alias") or body.alias,
            result_message=message,
            raw_response=result,
        )
        return {
            "success": True,
            "action": action,
            "target_ip": ip,
            "status": status_value,
            "message": message,
            "audit": audit,
            "error": None,
        }
    except Exception as e:
        message = str(e) or e.__class__.__name__
        audit = await _record_action(
            db,
            body_ip=ip,
            action_type=action,
            status="failed",
            user=user,
            reason=audit_reason,
            incident_id=body.incident_id,
            ticket_id=body.ticket_id,
            alias=body.alias,
            result_message=message,
            raw_response={"error": message},
        )
        return {
            "success": False,
            "action": action,
            "target_ip": ip,
            "status": "failed",
            "message": "Firewall action failed",
            "audit": audit,
            "error": message,
        }


@router.post("/block-ip")
async def block_ip(body: FirewallActionIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    if not _can_contain(user):
        raise HTTPException(status_code=403, detail="Containment action not permitted")
    ip = _validate_ip(body.ip)
    if not body.reason.strip():
        raise HTTPException(status_code=400, detail="Reason is required for block actions")
    try:
        result = PfSenseAdapter().add_to_alias(ip, body.alias)
        audit = await _record_action(
            db, body_ip=ip, action_type="block_ip", status="success", user=user,
            reason=body.reason, incident_id=body.incident_id, alias=result.get("alias") or body.alias,
            result_message=result.get("message") or "IP blocked", raw_response=result,
        )
        return {"success": True, "action": "block_ip", "ip": ip, "alias": audit["alias_name"], "audit": audit, "error": None}
    except Exception as e:
        audit = await _record_action(
            db, body_ip=ip, action_type="block_ip", status="failed", user=user,
            reason=body.reason, incident_id=body.incident_id, alias=body.alias,
            result_message=str(e) or e.__class__.__name__, raw_response={"error": str(e) or e.__class__.__name__},
        )
        return {"success": False, "action": "block_ip", "ip": ip, "alias": body.alias, "audit": audit, "error": audit["result_message"]}


@router.post("/unblock-ip")
async def unblock_ip(body: FirewallActionIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    if not _can_contain(user):
        raise HTTPException(status_code=403, detail="Containment action not permitted")
    ip = _validate_ip(body.ip)
    if not body.reason.strip():
        raise HTTPException(status_code=400, detail="Reason is required for unblock actions")
    try:
        result = PfSenseAdapter().remove_from_alias(ip, body.alias)
        audit = await _record_action(
            db, body_ip=ip, action_type="unblock_ip", status="success", user=user,
            reason=body.reason, incident_id=body.incident_id, alias=result.get("alias") or body.alias,
            result_message="IP unblocked", raw_response=result,
        )
        return {"success": True, "action": "unblock_ip", "ip": ip, "alias": audit["alias_name"], "audit": audit, "error": None}
    except Exception as e:
        audit = await _record_action(
            db, body_ip=ip, action_type="unblock_ip", status="failed", user=user,
            reason=body.reason, incident_id=body.incident_id, alias=body.alias,
            result_message=str(e) or e.__class__.__name__, raw_response={"error": str(e) or e.__class__.__name__},
        )
        return {"success": False, "action": "unblock_ip", "ip": ip, "alias": body.alias, "audit": audit, "error": audit["result_message"]}


@router.post("/check-ip")
async def check_ip(body: FirewallCheckIn, db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    ip = _validate_ip(body.ip)
    try:
        result = PfSenseAdapter().check_ip(ip, body.alias)
        audit = await _record_action(
            db, body_ip=ip, action_type="check_status", status="success", user=user,
            reason="Status check", incident_id=body.incident_id, alias=result.get("alias") or body.alias,
            result_message="Blocked" if result.get("blocked") else "Not blocked", raw_response=result,
        )
        return {"success": True, "ip": ip, "blocked": bool(result.get("blocked")), "alias": result.get("alias"), "audit": audit, "error": None}
    except Exception as e:
        audit = await _record_action(
            db, body_ip=ip, action_type="check_status", status="failed", user=user,
            reason="Status check", incident_id=body.incident_id, alias=body.alias,
            result_message=str(e) or e.__class__.__name__, raw_response={"error": str(e) or e.__class__.__name__},
        )
        return {"success": False, "ip": ip, "blocked": False, "alias": body.alias, "audit": audit, "error": audit["result_message"]}
