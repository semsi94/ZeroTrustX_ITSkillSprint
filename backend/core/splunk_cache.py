import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB

from db.session import SessionLocal


TIME_WINDOWS = {
    "Last 15m": timedelta(minutes=15),
    "Last 1h": timedelta(hours=1),
    "Last 4h": timedelta(hours=4),
    "Last 24h": timedelta(hours=24),
    "Last 7d": timedelta(days=7),
    "Last 30d": timedelta(days=30),
    "Last 90d": timedelta(days=90),
}


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text_value = str(value).strip()
    if not text_value:
        return None
    try:
        return datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except Exception:
        return None


def event_hash(event: dict) -> str:
    raw = event.get("raw") or event.get("raw_event") or event
    identity = {
        "id": event.get("id"),
        "time": event.get("time") or event.get("_time"),
        "index": event.get("index"),
        "sourcetype": event.get("sourcetype"),
        "host": event.get("host"),
        "message": event.get("message"),
        "raw": raw,
    }
    payload = json.dumps(identity, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def row_to_event(row) -> dict:
    raw = row["raw_event"] or {}
    return {
        "id": row["event_hash"][:16],
        "time": row["splunk_time"].isoformat() if row["splunk_time"] else "",
        "_time": row["splunk_time"].isoformat() if row["splunk_time"] else "",
        "index": row["index"] or "",
        "sourcetype": row["sourcetype"] or "",
        "host": row["host"] or "",
        "source": row["source"] or "",
        "source_ip": row["source_ip"] or "",
        "destination_ip": row["destination_ip"] or "",
        "destination_port": row["destination_port"] or "",
        "user": row["user_email"] or "",
        "email": row["user_email"] or "",
        "action": row["action"] or "",
        "category": row["category"] or "",
        "outcome": row["outcome"] or "",
        "method": row["method"] or "",
        "path": row["path"] or "",
        "original_url": row["original_url"] or "",
        "status_code": row["status_code"] or "",
        "severity": row["severity"] or "unknown",
        "message": row["message"] or "",
        "raw": raw,
        "cache_hit": True,
    }


async def cache_events(events: list[dict], ttl_hours: int = 168) -> dict:
    if not events:
        return {"cached": 0, "skipped": 0}
    cached = 0
    skipped = 0
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    async with SessionLocal() as db:
        for event in events:
            if not isinstance(event, dict):
                skipped += 1
                continue
            raw = event.get("raw") if isinstance(event.get("raw"), dict) else event
            h = event_hash(event)
            params = {
                "event_hash": h,
                "splunk_time": parse_time(event.get("time") or event.get("_time")),
                "index": event.get("index") or None,
                "sourcetype": event.get("sourcetype") or None,
                "host": event.get("host") or None,
                "source": event.get("source") or None,
                "source_ip": event.get("source_ip") or None,
                "destination_ip": event.get("destination_ip") or None,
                "destination_port": event.get("destination_port") or None,
                "user_email": event.get("email") or event.get("user") or None,
                "action": event.get("action") or None,
                "category": event.get("category") or None,
                "outcome": event.get("outcome") or None,
                "method": event.get("method") or None,
                "path": event.get("path") or None,
                "original_url": event.get("original_url") or None,
                "status_code": event.get("status_code") or event.get("error_status") or None,
                "severity": event.get("severity") or None,
                "message": event.get("message") or None,
                "raw_event": raw,
                "ttl_expires_at": expires_at,
            }
            stmt = text("""
                INSERT INTO splunk_cached_events (
                    event_hash, splunk_time, "index", sourcetype, host, source,
                    source_ip, destination_ip, destination_port, user_email,
                    action, category, outcome, method, path, original_url,
                    status_code, severity, message, raw_event, ttl_expires_at
                )
                VALUES (
                    :event_hash, :splunk_time, :index, :sourcetype, :host, :source,
                    :source_ip, :destination_ip, :destination_port, :user_email,
                    :action, :category, :outcome, :method, :path, :original_url,
                    :status_code, :severity, :message, :raw_event, :ttl_expires_at
                )
                ON CONFLICT (event_hash) DO UPDATE SET
                    ingest_time = NOW(),
                    ttl_expires_at = EXCLUDED.ttl_expires_at,
                    raw_event = EXCLUDED.raw_event
            """).bindparams(bindparam("raw_event", type_=JSONB))
            await db.execute(stmt, params)
            cached += 1
        await db.commit()
    return {"cached": cached, "skipped": skipped}


def _like(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return f"%{value}%" if value else None


async def search_cached_events(body) -> list[dict]:
    clauses = ["(ttl_expires_at IS NULL OR ttl_expires_at > NOW())"]
    params = {"limit": max(1, min(int(getattr(body, "limit", 100) or 100), 1000))}
    filters = getattr(body, "filters", None) if isinstance(getattr(body, "filters", None), dict) else {}
    time_range = getattr(body, "timeRange", None)
    if isinstance(time_range, dict):
        earliest = parse_time(time_range.get("earliest"))
        if earliest:
            params["from_time"] = earliest
            clauses.append("(splunk_time IS NULL OR splunk_time >= :from_time)")
        time_range = time_range.get("label")
    if time_range in TIME_WINDOWS:
        params["from_time"] = datetime.now(timezone.utc) - TIME_WINDOWS[time_range]
        clauses.append("(splunk_time IS NULL OR splunk_time >= :from_time)")
    elif time_range == "All time":
        pass
    else:
        earliest = parse_time(getattr(body, "earliest", None))
        if earliest:
            params["from_time"] = earliest
            clauses.append("(splunk_time IS NULL OR splunk_time >= :from_time)")

    index = (getattr(body, "index", None) or filters.get("index") or "").strip()
    if index and index not in {"*", "all"}:
        clauses.append('"index" = :index')
        params["index"] = index

    exact_map = {
        "source_ip": getattr(body, "source_ip", None) or getattr(body, "src_ip", None) or filters.get("source_ip"),
        "destination_ip": getattr(body, "destination_ip", None) or getattr(body, "dest_ip", None) or filters.get("destination_ip"),
        "status_code": getattr(body, "status_code", None) or filters.get("status_code"),
        "method": getattr(body, "method", None) or filters.get("method"),
        "severity": getattr(body, "severity", None) or filters.get("severity"),
    }
    for key, value in exact_map.items():
        if value:
            clauses.append(f"{key} = :{key}")
            params[key] = str(value)

    fuzzy = {
        "user_email": getattr(body, "user", None) or filters.get("user"),
        "host": getattr(body, "host", None) or filters.get("host"),
        "action": getattr(body, "action", None) or filters.get("action"),
        "path": getattr(body, "path", None) or filters.get("path"),
        "category": getattr(body, "category", None) or filters.get("category"),
        "message": getattr(body, "keyword", None) or filters.get("keyword") or filters.get("include_keyword"),
    }
    for key, value in fuzzy.items():
        like = _like(value)
        if like:
            clauses.append(f"{key} ILIKE :{key}")
            params[key] = like

    where = " AND ".join(clauses)
    async with SessionLocal() as db:
        rows = (await db.execute(text(f"""
            SELECT * FROM splunk_cached_events
            WHERE {where}
            ORDER BY splunk_time DESC NULLS LAST, ingest_time DESC
            LIMIT :limit
        """), params)).mappings().all()
    return [row_to_event(row) for row in rows]


async def search_cached_chain(event: dict, window_minutes: int, limit: int) -> list[dict]:
    clauses = ["(ttl_expires_at IS NULL OR ttl_expires_at > NOW())"]
    params = {"limit": max(1, min(int(limit or 50), 200))}
    ts = parse_time(event.get("time") or event.get("_time"))
    if ts:
        params["from_time"] = ts - timedelta(minutes=window_minutes)
        params["to_time"] = ts + timedelta(minutes=window_minutes)
        clauses.append("(splunk_time IS NULL OR splunk_time BETWEEN :from_time AND :to_time)")
    index = (event.get("index") or "").strip()
    if index and index not in {"*", "all"}:
        clauses.append('"index" = :index')
        params["index"] = index

    identity = []
    if event.get("source_ip"):
        identity.append("source_ip = :source_ip")
        params["source_ip"] = event["source_ip"]
    if event.get("user") or event.get("email"):
        identity.append("user_email = :user_email")
        params["user_email"] = event.get("user") or event.get("email")
    if event.get("host"):
        identity.append("host = :host")
        params["host"] = event["host"]
    if not identity:
        return []
    clauses.append("(" + " OR ".join(identity) + ")")
    where = " AND ".join(clauses)
    async with SessionLocal() as db:
        rows = (await db.execute(text(f"""
            SELECT * FROM splunk_cached_events
            WHERE {where}
            ORDER BY splunk_time ASC NULLS LAST, ingest_time ASC
            LIMIT :limit
        """), params)).mappings().all()
    return [row_to_event(row) for row in rows]


async def clear_cache() -> int:
    async with SessionLocal() as db:
        deleted = (await db.execute(text("DELETE FROM splunk_cached_events"))).rowcount or 0
        await db.commit()
    return int(deleted)
