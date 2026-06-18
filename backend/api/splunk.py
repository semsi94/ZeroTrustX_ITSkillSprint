import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from adapters.splunk_adapter import SplunkAdapter, ensure_search_prefix
from api.deps import current_user, current_user_token
from core.splunk_cache import cache_events, clear_cache, search_cached_chain, search_cached_events
from core.splunk_queries import append_head, build_search, escape_spl_value, index_clause, resolve_time
from db.session import get_db

log = logging.getLogger("zerotrustx.api.splunk")

router = APIRouter(prefix="/api/splunk", tags=["splunk"])
DANGEROUS_SPL_RE = re.compile(r"(^|\|\s*)(delete|outputlookup|collect|script|sendemail|map|rest)\b", re.I)
RATE_LIMIT: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 45


class SearchIn(BaseModel):
    mode: Optional[str] = None
    spl: Optional[str] = None
    index: Optional[str] = None
    timeRange: Optional[Any] = None
    earliest: Optional[str] = None
    latest: Optional[str] = "now"
    limit: int = Field(100, ge=1, le=1000)
    filters: dict[str, Any] = Field(default_factory=dict)
    selectedAlertIds: list[str] = Field(default_factory=list)
    selectedReportIds: list[str] = Field(default_factory=list)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    sourcetype: Optional[str] = None
    source: Optional[str] = None
    action: Optional[str] = None
    status_code: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    authenticated: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    keyword: Optional[str] = None
    exclude_keyword: Optional[str] = None
    refresh: bool = False


class SearchFromSavedIn(BaseModel):
    savedSearchIds: list[str] = Field(default_factory=list)
    alertIds: list[str] = Field(default_factory=list)
    reportIds: list[str] = Field(default_factory=list)
    timeRange: Optional[Any] = "Last 24h"
    limit: int = Field(100, ge=1, le=1000)


class LogChainIn(BaseModel):
    event: dict
    windowMinutes: int = Field(10, ge=1, le=120)
    limit: int = Field(50, ge=1, le=200)


class SyncCacheIn(BaseModel):
    timeRange: Optional[Any] = "Last 24h"
    limit: int = Field(1000, ge=1, le=2500)


def safe_search_response(
    events=None,
    query: str = "",
    error: Optional[str] = None,
    *,
    source: str = "splunk",
    cache_used: bool = False,
    time_range: Optional[dict] = None,
    groups: Optional[list] = None,
) -> dict:
    rows = events if isinstance(events, list) else []
    return {
        "events": rows,
        "count": len(rows),
        "source": source,
        "query": query,
        "timeRange": time_range,
        "cacheUsed": cache_used,
        "groups": groups or [],
        "error": error,
    }


def _adapter() -> SplunkAdapter:
    return SplunkAdapter()


def _search_cache_key(body: SearchIn, query: str) -> str:
    payload = {
        "mode": body.mode,
        "spl": body.spl,
        "index": body.index,
        "timeRange": body.timeRange,
        "earliest": body.earliest,
        "latest": body.latest,
        "limit": body.limit,
        "filters": body.filters,
        "selectedAlertIds": body.selectedAlertIds,
        "selectedReportIds": body.selectedReportIds,
        "query": query,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _cacheable(body: SearchIn) -> bool:
    return body.limit <= 500 and not (body.spl and DANGEROUS_SPL_RE.search(body.spl))


async def _read_search_cache(db: Optional[AsyncSession], cache_key: str) -> Optional[dict]:
    if db is None:
        return None
    try:
        row = (await db.execute(text("""
            SELECT normalized_events, query
            FROM investigation_search_cache
            WHERE cache_key = :cache_key AND expires_at > NOW()
        """), {"cache_key": cache_key})).mappings().first()
        if not row:
            return None
        cached = row.get("normalized_events") or {}
        events = cached.get("events") if isinstance(cached, dict) else []
        response = safe_search_response(
            events,
            row.get("query") or "",
            None,
            source="cache",
            cache_used=True,
            time_range=cached.get("timeRange") if isinstance(cached, dict) else None,
            groups=cached.get("groups") if isinstance(cached, dict) else [],
        )
        response["count"] = len(events if isinstance(events, list) else [])
        return response
    except Exception as e:
        log.info("Saved investigation cache read skipped: %s", e)
        return None


async def _write_search_cache(db: Optional[AsyncSession], cache_key: str, query: str, response: dict) -> None:
    if db is None:
        return
    try:
        events = response.get("events") if isinstance(response.get("events"), list) else []
        payload = {
            "events": events,
            "groups": response.get("groups") or [],
            "timeRange": response.get("timeRange"),
        }
        stmt = text("""
            INSERT INTO investigation_search_cache (
                cache_key, query, expires_at, result_count, normalized_events
            )
            VALUES (:cache_key, :query, NOW() + INTERVAL '10 minutes', :result_count, :payload)
            ON CONFLICT (cache_key) DO UPDATE SET
                query = EXCLUDED.query,
                created_at = NOW(),
                expires_at = EXCLUDED.expires_at,
                result_count = EXCLUDED.result_count,
                normalized_events = EXCLUDED.normalized_events
        """).bindparams(bindparam("payload", type_=JSONB))
        await db.execute(stmt, {
            "cache_key": cache_key,
            "query": query,
            "result_count": len(events),
            "payload": payload,
        })
        await db.commit()
    except Exception as e:
        log.info("Saved investigation cache write skipped: %s", e)


def _rate_limit(user: dict) -> None:
    key = user.get("username") or "unknown"
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    bucket = [ts for ts in RATE_LIMIT.get(key, []) if ts >= cutoff]
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many search requests. Wait a minute and try again.")
    bucket.append(now)
    RATE_LIMIT[key] = bucket


def _validate_ip(value: Optional[str], field: str) -> None:
    if not value:
        return
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {field}")


def _time_range_parts(value: Any, earliest: Optional[str] = None, latest: Optional[str] = "now") -> dict:
    if isinstance(value, dict):
        label = str(value.get("label") or value.get("preset") or "Custom")
        e = str(value.get("earliest") or earliest or "-24h")
        l = str(value.get("latest") or latest or "now")
    else:
        label = str(value or "Last 24h")
        e, l = resolve_time(label, earliest, latest)
    e, l = resolve_time(None, e, l)
    if not e or not l:
        raise HTTPException(status_code=400, detail="Invalid time range")
    try:
        if "T" in e and "T" in l:
            start = datetime.fromisoformat(e.replace("Z", "+00:00"))
            end = datetime.fromisoformat(l.replace("Z", "+00:00"))
            if start >= end:
                raise HTTPException(status_code=400, detail="Absolute start time must be before end time")
    except HTTPException:
        raise
    except Exception:
        pass
    return {"earliest": e, "latest": l, "label": label}


def _time_range_label(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("label") or "Custom")
    return str(value or "Last 24h")


def _validate_search(body: SearchIn) -> None:
    valid_ranges = {
        "Last 15m", "Last 15 minutes", "Last 1h", "Last 1 hour",
        "Last 4h", "Last 4 hours", "Last 24h", "Last 24 hours",
        "Last 7d", "Last 7 days", "Last 30d", "Last 30 days",
        "Last 90d", "Last 90 days", "All time", "Custom", None,
    }
    if not isinstance(body.timeRange, dict) and body.timeRange not in valid_ranges:
        raise HTTPException(status_code=400, detail="Invalid time range")
    filters = body.filters if isinstance(body.filters, dict) else {}
    _validate_ip(body.source_ip or body.src_ip or filters.get("source_ip"), "source_ip")
    _validate_ip(body.destination_ip or body.dest_ip or filters.get("destination_ip"), "destination_ip")
    if body.spl and DANGEROUS_SPL_RE.search(body.spl):
        raise HTTPException(
            status_code=400,
            detail="Advanced SPL contains a blocked command for this dashboard",
        )


def _build_from_body(body: SearchIn, adapter: SplunkAdapter, force_index_all: bool = False) -> str:
    filters = body.filters if isinstance(body.filters, dict) else {}
    time_parts = _time_range_parts(body.timeRange, body.earliest, body.latest)
    return build_search(
        adapter,
        spl=body.spl,
        index=body.index or filters.get("index"),
        time_range=None,
        earliest=time_parts["earliest"],
        latest=time_parts["latest"],
        limit=body.limit,
        source_ip=body.source_ip or body.src_ip or filters.get("source_ip"),
        destination_ip=body.destination_ip or body.dest_ip or filters.get("destination_ip"),
        user=body.user or filters.get("user"),
        host=body.host or filters.get("host"),
        sourcetype=body.sourcetype or filters.get("sourcetype"),
        source=body.source or filters.get("source"),
        action=body.action or filters.get("action"),
        status_code=body.status_code or filters.get("status_code"),
        method=body.method or filters.get("method"),
        path=body.path or filters.get("path"),
        user_agent=body.user_agent or filters.get("user_agent"),
        authenticated=body.authenticated or filters.get("authenticated"),
        category=body.category or filters.get("category"),
        severity=body.severity or filters.get("severity"),
        keyword=body.keyword or filters.get("keyword") or filters.get("include_keyword"),
        exclude_keyword=body.exclude_keyword or filters.get("exclude_keyword"),
        force_index_all=force_index_all,
    )


async def execute_search(body: SearchIn, db: Optional[AsyncSession] = None) -> dict:
    _validate_search(body)
    adapter = _adapter()
    query = _build_from_body(body, adapter)
    time_parts = _time_range_parts(body.timeRange, body.earliest, body.latest)
    cache_key = _search_cache_key(body, query)
    log.info("Splunk API generated SPL: %s", query)

    if not adapter.is_configured():
        return safe_search_response(query=query, error=f"Splunk is not configured: missing {', '.join(adapter.missing_keys())}", time_range=time_parts)

    if not body.refresh and _cacheable(body):
        cached = await _read_search_cache(db, cache_key)
        if cached:
            return cached

    if body.selectedAlertIds or body.selectedReportIds:
        saved = await _execute_saved_searches(
            adapter,
            alert_ids=body.selectedAlertIds,
            report_ids=body.selectedReportIds,
            saved_ids=[],
            time_range=body.timeRange or {"label": time_parts["label"], "earliest": time_parts["earliest"], "latest": time_parts["latest"]},
            limit=body.limit,
            post_filter=_post_filter_from_body(body),
        )
        events = []
        for group in saved["groups"]:
            events.extend([{**event, "matched_saved_search": group["savedSearchName"]} for event in group["events"]])
        response = safe_search_response(
            events,
            query=query,
            error=saved.get("error"),
            source="splunk",
            cache_used=False,
            time_range=time_parts,
            groups=saved["groups"],
        )
        if _cacheable(body) and not response.get("error"):
            await _write_search_cache(db, cache_key, query, response)
        return response

    if not body.spl:
        try:
            cached_rows = await search_cached_events(body)
            if cached_rows:
                return safe_search_response(cached_rows, query, source="cache", cache_used=True, time_range=time_parts)
        except Exception as cache_err:
            log.info("Splunk cache lookup skipped: %s", cache_err)

    result = await asyncio.to_thread(adapter.export_search, query)
    events = result.get("events") if isinstance(result, dict) else []
    error = result.get("error") if isinstance(result, dict) else "Splunk search failed"
    if events:
        try:
            await cache_events(events)
        except Exception as cache_err:
            log.info("Splunk cache write skipped: %s", cache_err)

    if not error and not events and not body.spl and (adapter.default_index or "*").strip() not in {"", "*"}:
        fallback_query = _build_from_body(body, adapter, force_index_all=True)
        fallback = await asyncio.to_thread(adapter.export_search, fallback_query)
        fallback_events = fallback.get("events") if isinstance(fallback, dict) else []
        fallback_error = fallback.get("error") if isinstance(fallback, dict) else None
        if fallback_events:
            try:
                await cache_events(fallback_events)
            except Exception as cache_err:
                log.info("Splunk fallback cache write skipped: %s", cache_err)
        if fallback_events or fallback_error:
            response = safe_search_response(fallback_events, fallback_query, fallback_error, time_range=time_parts)
            if _cacheable(body) and not response.get("error"):
                await _write_search_cache(db, cache_key, fallback_query, response)
            return response

    response = safe_search_response(events, query, error, time_range=time_parts)
    if _cacheable(body) and not response.get("error"):
        await _write_search_cache(db, cache_key, query, response)
    return response


def _post_filter_from_body(body: SearchIn) -> str:
    filters = body.filters if isinstance(body.filters, dict) else {}
    parts = []
    source_ip = body.source_ip or body.src_ip or filters.get("source_ip")
    destination_ip = body.destination_ip or body.dest_ip or filters.get("destination_ip")
    user_value = body.user or filters.get("user")
    host_value = body.host or filters.get("host")
    action_value = body.action or filters.get("action")
    status_code = body.status_code or filters.get("status_code")
    keyword = body.keyword or filters.get("keyword") or filters.get("include_keyword")
    if source_ip:
        v = escape_spl_value(source_ip)
        parts.append(f'(source_ip="{v}" OR src_ip="{v}" OR src="{v}" OR clientip="{v}" OR client_ip="{v}")')
    if destination_ip:
        v = escape_spl_value(destination_ip)
        parts.append(f'(destination_ip="{v}" OR dest_ip="{v}" OR dest="{v}" OR dst="{v}")')
    if user_value:
        v = escape_spl_value(user_value)
        parts.append(f'(user="{v}" OR username="{v}" OR email="{v}" OR details.email="{v}" OR details.payload.email="{v}" OR user.name="{v}")')
    if host_value:
        v = escape_spl_value(host_value)
        parts.append(f'(host="{v}" OR hostname="{v}" OR computer_name="{v}" OR dest_host="{v}")')
    if action_value:
        v = escape_spl_value(action_value)
        parts.append(f'(action="*{v}*" OR event_category="*{v}*" OR message="*{v}*" OR signature="*{v}*" OR rule_name="*{v}*" OR alert.signature="*{v}*")')
    if status_code:
        v = escape_spl_value(status_code)
        parts.append(f'(status_code="{v}" OR status="{v}" OR details.error.status="{v}")')
    if keyword:
        v = escape_spl_value(keyword)
        parts.append(f'(_raw="*{v}*" OR message="*{v}*" OR signature="*{v}*" OR rule_name="*{v}*" OR action="*{v}*" OR event_category="*{v}*")')
    return " ".join(parts)


def _saved_with_time(search: str, time_range: Any, limit: int, post_filter: str = "") -> str:
    query = ensure_search_prefix(search or "index=*")
    parts = _time_range_parts(time_range, None, "now")
    earliest, latest = parts["earliest"], parts["latest"]
    base, sep, rest = query.partition("|")
    if "earliest=" not in base.lower():
        base = f"{base.strip()} earliest={earliest}"
    if "latest=" not in base.lower():
        base = f"{base.strip()} latest={latest}"
    query = f"{base} |{rest}" if sep else base
    if post_filter:
        query = f"{query.strip()} | search {post_filter}"
    return append_head(query.strip(), limit)


async def _execute_saved_searches(
    adapter: SplunkAdapter,
    *,
    alert_ids: list[str],
    report_ids: list[str],
    saved_ids: list[str],
    time_range: Any,
    limit: int,
    post_filter: str = "",
) -> dict:
    groups = []
    saved_data = await asyncio.to_thread(adapter.list_saved_searches)
    saved_items = saved_data.get("items", [])
    by_id = {}
    for item in saved_items:
        for key in (item.get("id"), item.get("name"), item.get("title")):
            if key:
                by_id[str(key)] = item

    selected_ids = list(dict.fromkeys([*saved_ids, *alert_ids, *report_ids]))[:6]
    for saved_id in selected_ids:
        item = by_id.get(str(saved_id))
        if not item:
            groups.append({
                "savedSearchName": str(saved_id),
                "query": "",
                "events": [],
                "count": 0,
                "error": "Saved search not found",
            })
            continue
        query = _saved_with_time(item.get("search") or "index=*", time_range or "Last 24h", limit, post_filter=post_filter)
        result = await asyncio.to_thread(adapter.export_search, query)
        events = result.get("events") if isinstance(result, dict) else []
        if events:
            try:
                await cache_events(events)
            except Exception as cache_err:
                log.info("Saved search cache write skipped: %s", cache_err)
        groups.append({
            "savedSearchName": item.get("title") or item.get("name") or str(saved_id),
            "savedSearchType": item.get("type") or "saved_search",
            "query": query,
            "events": events if isinstance(events, list) else [],
            "count": len(events) if isinstance(events, list) else 0,
            "error": result.get("error") if isinstance(result, dict) else "Splunk search failed",
        })

    return {
        "groups": groups,
        "totalCount": sum(g["count"] for g in groups),
        "source": "splunk",
        "error": saved_data.get("error") if not groups else None,
    }


@router.post("/search")
async def search(
    body: SearchIn,
    user: dict = Depends(current_user_token),
    db: AsyncSession = Depends(get_db),
):
    _rate_limit(user)
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewer cannot run investigations")
    try:
        return await execute_search(body, db)
    except HTTPException:
        raise
    except Exception as e:
        msg = str(e) or e.__class__.__name__
        log.info("Splunk search route failed: %s", msg)
        return safe_search_response(error=msg)


@router.get("/saved-searches")
async def saved_searches(user: dict = Depends(current_user_token)):
    _rate_limit(user)
    try:
        data = await asyncio.to_thread(_adapter().list_saved_searches)
        return {"items": data.get("items", []), "count": len(data.get("items", [])), "source": "splunk", "error": data.get("error")}
    except Exception as e:
        return {"items": [], "count": 0, "source": "splunk", "error": str(e) or e.__class__.__name__}


@router.get("/reports")
async def reports(user: dict = Depends(current_user_token)):
    _rate_limit(user)
    try:
        data = await asyncio.to_thread(_adapter().list_saved_searches)
        items = [
            item for item in data.get("items", [])
            if item.get("type") in {"report", "saved_search"}
        ]
        return {"items": items, "count": len(items), "source": "splunk", "error": data.get("error")}
    except Exception as e:
        return {"items": [], "count": 0, "source": "splunk", "error": str(e) or e.__class__.__name__}


@router.get("/alerts")
async def alerts(user: dict = Depends(current_user_token)):
    _rate_limit(user)
    try:
        data = await asyncio.to_thread(_adapter().list_fired_alerts)
        return {"items": data.get("items", []), "count": len(data.get("items", [])), "source": "splunk", "error": data.get("error")}
    except Exception as e:
        return {"items": [], "count": 0, "source": "splunk", "error": str(e) or e.__class__.__name__}


@router.post("/search-from-saved")
async def search_from_saved(body: SearchFromSavedIn, user: dict = Depends(current_user_token)):
    _rate_limit(user)
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewer cannot run investigations")
    adapter = _adapter()
    try:
        return await _execute_saved_searches(
            adapter,
            alert_ids=body.alertIds,
            report_ids=body.reportIds,
            saved_ids=body.savedSearchIds,
            time_range=body.timeRange,
            limit=body.limit,
            post_filter="",
        )
    except Exception as e:
        return {
            "groups": [],
            "totalCount": 0,
            "source": "splunk",
            "error": str(e) or e.__class__.__name__,
        }


def _event_time_window(event: dict, minutes: int) -> tuple[str, str]:
    value = event.get("time") or event.get("_time")
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return "-24h", "now"
    earliest = (dt - timedelta(minutes=minutes)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    latest = (dt + timedelta(minutes=minutes)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return earliest, latest


@router.post("/log-chain")
async def log_chain(body: LogChainIn, user: dict = Depends(current_user_token)):
    _rate_limit(user)
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewer cannot run investigations")
    event = body.event if isinstance(body.event, dict) else {}
    adapter = _adapter()
    earliest, latest = _event_time_window(event, body.windowMinutes)
    identity_clauses = []
    for field, value in (
        ("source_ip", event.get("source_ip")),
        ("user", event.get("user") or event.get("email")),
        ("host", event.get("host")),
    ):
        if value:
            identity_clauses.append((field, value))

    if not identity_clauses:
        return safe_search_response(query="", error="Log chain needs source IP, user, or host context")

    or_parts = []
    if event.get("source_ip"):
        value = escape_spl_value(event["source_ip"])
        or_parts.append(f'(source_ip="{value}" OR src_ip="{value}" OR src="{value}" OR clientip="{value}" OR client_ip="{value}")')
    if event.get("user") or event.get("email"):
        value = escape_spl_value(event.get("user") or event.get("email"))
        or_parts.append(f'(user="{value}" OR username="{value}" OR email="{value}" OR details.email="{value}" OR details.payload.email="{value}" OR user.name="{value}")')
    if event.get("host"):
        value = escape_spl_value(event["host"])
        or_parts.append(f'(host="{value}" OR hostname="{value}" OR computer_name="{value}" OR dest_host="{value}")')
    query = f"search {index_clause(adapter, event.get('index') or '*')} earliest={earliest} latest={latest} ({' OR '.join(or_parts)}) | head {body.limit}"
    log.info("Splunk log-chain SPL: %s", query)
    try:
        cached_rows = await search_cached_chain(event, body.windowMinutes, body.limit)
        if cached_rows:
            return safe_search_response(cached_rows, query, source="cache", cache_used=True)
    except Exception as cache_err:
        log.info("Log-chain cache lookup skipped: %s", cache_err)

    if not adapter.is_configured():
        return safe_search_response(query=query, error=f"Splunk is not configured: missing {', '.join(adapter.missing_keys())}")
    result = await asyncio.to_thread(adapter.export_search, query)
    events = result.get("events") if isinstance(result, dict) else []
    if events:
        try:
            await cache_events(events)
        except Exception as cache_err:
            log.info("Log-chain cache write skipped: %s", cache_err)
    return safe_search_response(events, query, result.get("error") if isinstance(result, dict) else None)


@router.post("/cache/sync")
async def sync_cache(body: SyncCacheIn, user: dict = Depends(current_user_token)):
    _rate_limit(user)
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewer cannot sync Splunk cache")
    adapter = _adapter()
    query = _build_from_body(SearchIn(timeRange=body.timeRange, limit=body.limit), adapter)
    if not adapter.is_configured():
        return {
            "success": False,
            "cached": 0,
            "skipped": 0,
            "source": "splunk",
            "error": f"Splunk is not configured: missing {', '.join(adapter.missing_keys())}",
        }
    result = await asyncio.to_thread(adapter.export_search, query)
    events = result.get("events") if isinstance(result, dict) else []
    cache_result = {"cached": 0, "skipped": 0}
    if events:
        cache_result = await cache_events(events)
    return {
        "success": result.get("error") is None if isinstance(result, dict) else False,
        "cached": cache_result["cached"],
        "skipped": cache_result["skipped"],
        "source": "splunk",
        "error": result.get("error") if isinstance(result, dict) else "Splunk cache sync failed",
    }


@router.post("/cache/clear")
async def clear_splunk_cache(user: dict = Depends(current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    deleted = await clear_cache()
    return {"success": True, "cacheCleared": True, "deletedCachedEvents": deleted, "error": None}
