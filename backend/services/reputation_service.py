from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from adapters.abuseipdb_adapter import AbuseIpdbAdapter
from adapters.virustotal_adapter import VirusTotalAdapter
from config import get_settings
from services.demo_mode import demo_provider_status, is_demo_mode

log = logging.getLogger(__name__)

IP_FIELDS = (
    "source_ip", "src_ip", "client_ip", "clientip", "destination_ip", "dest_ip",
    "dst", "remote_addr", "user_ip", "ip",
)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return bool(parsed.is_global and not parsed.is_multicast and not parsed.is_reserved and not parsed.is_loopback and not parsed.is_link_local)


def extract_unique_public_ips(events: list[dict]) -> tuple[list[str], int]:
    found: set[str] = set()
    skipped_private = 0
    for event in events or []:
        if not isinstance(event, dict):
            continue
        candidates: list[str] = []
        for field in IP_FIELDS:
            value = event.get(field)
            if value:
                candidates.append(str(value))
        raw = event.get("raw_event") or event.get("raw_data") or event.get("raw") or {}
        if isinstance(raw, dict):
            for field in IP_FIELDS:
                value = raw.get(field)
                if value:
                    candidates.append(str(value))
        text_blob = " ".join(candidates + [
            json.dumps(raw, default=str)[:8000] if isinstance(raw, (dict, list)) else str(raw or "")[:8000],
            json.dumps(event, default=str)[:8000],
        ])
        for match in IP_RE.findall(text_blob):
            try:
                normalized = str(ipaddress.ip_address(match))
            except ValueError:
                continue
            if is_public_ip(normalized):
                found.add(normalized)
            else:
                skipped_private += 1
    return sorted(found), skipped_private


def _parse_dt(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _ttl_for(verdict: str) -> timedelta:
    settings = get_settings()
    if verdict == "malicious":
        return timedelta(hours=8)
    if verdict == "suspicious":
        return timedelta(hours=18)
    if verdict == "error":
        return timedelta(minutes=20)
    if verdict == "clean":
        return timedelta(hours=60)
    return timedelta(hours=max(1, settings.IP_REPUTATION_DEFAULT_CACHE_HOURS))


def normalize_provider_results(ip: str, abuse: dict, vt: dict) -> dict:
    abuse_ok = bool(abuse.get("success"))
    vt_ok = bool(vt.get("success"))
    abuse_score = int(abuse.get("abuseConfidenceScore") or 0) if abuse_ok else None
    vt_stats = vt.get("last_analysis_stats") or {}
    vt_malicious = int(vt_stats.get("malicious") or 0) if vt_ok else None
    vt_suspicious = int(vt_stats.get("suspicious") or 0) if vt_ok else None
    vt_reputation = vt.get("reputation") if vt_ok else None

    provider_errors = [item.get("error") for item in (abuse, vt) if not item.get("success") and item.get("error")]
    if abuse_ok or vt_ok:
        if (abuse_score or 0) >= 75 or (vt_malicious or 0) > 0:
            verdict = "malicious"
        elif (abuse_score or 0) >= 25 or (vt_suspicious or 0) > 0:
            verdict = "suspicious"
        elif abuse_ok and vt_ok:
            verdict = "clean"
        else:
            verdict = "unknown"
    else:
        verdict = "error"

    vt_component = min(100, (vt_malicious or 0) * 35 + (vt_suspicious or 0) * 15)
    rep_component = 0
    if isinstance(vt_reputation, int) and vt_reputation < 0:
        rep_component = min(30, abs(vt_reputation))
    score = max(abuse_score or 0, vt_component, rep_component)
    if verdict == "clean":
        score = 0

    now = datetime.now(timezone.utc)
    return {
        "ip_address": ip,
        "is_public": True,
        "overall_score": int(max(0, min(100, score))),
        "overall_verdict": verdict,
        "abuseipdb_score": abuse_score,
        "abuseipdb_total_reports": abuse.get("totalReports") if abuse_ok else None,
        "abuseipdb_country_code": abuse.get("countryCode") if abuse_ok else None,
        "abuseipdb_usage_type": abuse.get("usageType") if abuse_ok else None,
        "abuseipdb_isp": abuse.get("isp") if abuse_ok else None,
        "abuseipdb_domain": abuse.get("domain") if abuse_ok else None,
        "abuseipdb_last_reported_at": _parse_dt(abuse.get("lastReportedAt")) if abuse_ok else None,
        "virustotal_malicious": vt_malicious,
        "virustotal_suspicious": vt_suspicious,
        "virustotal_harmless": int(vt_stats.get("harmless") or 0) if vt_ok else None,
        "virustotal_undetected": int(vt_stats.get("undetected") or 0) if vt_ok else None,
        "virustotal_reputation": vt_reputation if isinstance(vt_reputation, int) else None,
        "virustotal_country": vt.get("country") if vt_ok else None,
        "virustotal_as_owner": vt.get("as_owner") if vt_ok else None,
        "virustotal_network": vt.get("network") if vt_ok else None,
        "provider_sources": {"abuseipdb": _public_abuse(abuse), "virustotal": _public_vt(vt)},
        "raw_abuseipdb": abuse.get("raw") if abuse_ok else None,
        "raw_virustotal": vt.get("raw") if vt_ok else None,
        "last_checked_at": now,
        "expires_at": now + _ttl_for(verdict),
        "error_message": "; ".join(provider_errors)[:1000] if provider_errors else None,
        "source_tools": [name for name, ok in (("abuseipdb", abuse_ok), ("virustotal", vt_ok)) if ok],
    }


def _public_abuse(data: dict) -> dict:
    return {
        "success": bool(data.get("success")),
        "score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "error": data.get("error"),
    }


def _public_vt(data: dict) -> dict:
    stats = data.get("last_analysis_stats") or {}
    return {
        "success": bool(data.get("success")),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "reputation": data.get("reputation"),
        "error": data.get("error"),
    }


async def get_cached_reputation(db: AsyncSession, ip: str) -> dict | None:
    row = (await db.execute(text("SELECT * FROM ip_reputation WHERE ip_address = :ip"), {"ip": ip})).mappings().first()
    return reputation_to_dict(row) if row else None


def reputation_to_dict(row, include_raw: bool = False) -> dict:
    if not row:
        return {}
    data = {
        "id": str(row["id"]),
        "ip_address": row.get("ip_address"),
        "is_public": bool(row.get("is_public")),
        "overall_score": int(row.get("overall_score") or 0),
        "overall_verdict": row.get("overall_verdict") or "unknown",
        "abuseipdb_score": row.get("abuseipdb_score"),
        "abuseipdb_total_reports": row.get("abuseipdb_total_reports"),
        "abuseipdb_country_code": row.get("abuseipdb_country_code"),
        "abuseipdb_usage_type": row.get("abuseipdb_usage_type"),
        "abuseipdb_isp": row.get("abuseipdb_isp"),
        "abuseipdb_domain": row.get("abuseipdb_domain"),
        "abuseipdb_last_reported_at": row["abuseipdb_last_reported_at"].isoformat() if row.get("abuseipdb_last_reported_at") else None,
        "virustotal_malicious": row.get("virustotal_malicious"),
        "virustotal_suspicious": row.get("virustotal_suspicious"),
        "virustotal_harmless": row.get("virustotal_harmless"),
        "virustotal_undetected": row.get("virustotal_undetected"),
        "virustotal_reputation": row.get("virustotal_reputation"),
        "virustotal_country": row.get("virustotal_country"),
        "virustotal_as_owner": row.get("virustotal_as_owner"),
        "virustotal_network": row.get("virustotal_network"),
        "provider_sources": row.get("provider_sources") or {},
        "first_seen_at": row["first_seen_at"].isoformat() if row.get("first_seen_at") else None,
        "last_seen_at": row["last_seen_at"].isoformat() if row.get("last_seen_at") else None,
        "last_checked_at": row["last_checked_at"].isoformat() if row.get("last_checked_at") else None,
        "expires_at": row["expires_at"].isoformat() if row.get("expires_at") else None,
        "error_message": row.get("error_message"),
    }
    if include_raw:
        data["raw_abuseipdb"] = row.get("raw_abuseipdb")
        data["raw_virustotal"] = row.get("raw_virustotal")
    return data


async def upsert_observation(db: AsyncSession, ip: str, source_system: str = "unknown", incident_id: str | None = None, evidence_id: str | None = None, event_hash: str | None = None, field_name: str | None = None) -> None:
    digest = event_hash or hashlib.sha256(f"{ip}|{source_system}|{incident_id}|{evidence_id}|{field_name}".encode()).hexdigest()
    params = {
        "ip": ip,
        "source_system": source_system or "unknown",
        "incident_id": incident_id,
        "evidence_id": evidence_id,
        "event_hash": digest,
        "field_name": field_name,
    }
    existing = (await db.execute(text("""
        SELECT id FROM ip_observations
        WHERE ip_address = :ip
          AND source_system = :source_system
          AND COALESCE(incident_id::text, '') = COALESCE(:incident_id, '')
          AND COALESCE(evidence_id::text, '') = COALESCE(:evidence_id, '')
          AND COALESCE(event_hash, '') = COALESCE(:event_hash, '')
          AND COALESCE(field_name, '') = COALESCE(:field_name, '')
        LIMIT 1
    """), params)).scalar()
    if existing:
        await db.execute(text("UPDATE ip_observations SET last_seen_at = NOW(), occurrence_count = occurrence_count + 1 WHERE id = :id"), {"id": str(existing)})
    else:
        await db.execute(text("""
            INSERT INTO ip_observations (ip_address, source_system, incident_id, evidence_id, event_hash, field_name)
            VALUES (:ip, :source_system, :incident_id, :evidence_id, :event_hash, :field_name)
        """), params)


async def enrich_from_events(db: AsyncSession, events: list[dict], incident_id: str | None = None, source_system: str = "investigation", force: bool = False) -> dict:
    ips, skipped = extract_unique_public_ips(events)
    return await enqueue_or_cache_ips(db, ips, incident_id=incident_id, source_system=source_system, force=force)


async def enqueue_or_cache_ips(db: AsyncSession, ips: list[str], incident_id: str | None = None, source_system: str = "unknown", force: bool = False) -> dict:
    queued = cached = skipped_private = 0
    clean_ips: list[str] = []
    now = datetime.now(timezone.utc)
    for raw_ip in sorted(set(ips or [])):
        try:
            ip = str(ipaddress.ip_address(str(raw_ip).strip()))
        except ValueError:
            skipped_private += 1
            continue
        if not is_public_ip(ip):
            skipped_private += 1
            continue
        clean_ips.append(ip)
        await upsert_observation(db, ip, source_system=source_system, incident_id=incident_id)
        row = (await db.execute(text("SELECT expires_at FROM ip_reputation WHERE ip_address = :ip"), {"ip": ip})).mappings().first()
        if row and row.get("expires_at") and row["expires_at"] > now and not force:
            cached += 1
            continue
        queued += 1
        try:
            from workers.reputation_tasks import enrich_ip_task
            enrich_ip_task.delay(ip, incident_id)
        except Exception:
            log.exception("Failed to enqueue reputation enrichment for %s", ip)
    await db.commit()
    return {"success": True, "queued": queued, "cached": cached, "skipped_private": skipped_private, "ips": clean_ips, "error": None}


async def enrich_ip_now(db: AsyncSession, ip: str, incident_id: str | None = None, force: bool = False) -> dict:
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"success": False, "error": "Invalid IP address"}
    if not is_public_ip(normalized_ip):
        return {"success": True, "skipped_private": 1, "ip": normalized_ip, "reputation": None, "error": None}
    now = datetime.now(timezone.utc)
    cached = (await db.execute(text("SELECT * FROM ip_reputation WHERE ip_address = :ip"), {"ip": normalized_ip})).mappings().first()
    if cached and cached.get("expires_at") and cached["expires_at"] > now and not force:
        return {"success": True, "cached": True, "ip": normalized_ip, "reputation": reputation_to_dict(cached), "error": None}
    settings = get_settings()
    if not settings.IP_REPUTATION_ENABLED:
        return {"success": False, "error": "IP reputation is disabled"}
    recent_checks = int((await db.execute(text("""
        SELECT COUNT(*) FROM ip_reputation
        WHERE last_checked_at >= NOW() - INTERVAL '1 minute'
    """))).scalar() or 0)
    if recent_checks >= max(1, int(settings.IP_REPUTATION_MAX_REQUESTS_PER_MINUTE or 50)):
        return {"success": False, "ip": normalized_ip, "rate_limited": True, "error": "IP reputation provider rate limit reached; retry shortly"}
    abuse = AbuseIpdbAdapter().check_ip(normalized_ip)
    vt = VirusTotalAdapter().check_ip(normalized_ip)
    result = normalize_provider_results(normalized_ip, abuse, vt)
    row = await save_reputation_result(db, result)
    if incident_id:
        await link_incident_reputation(db, incident_id, normalized_ip, str(row["id"]), result)
    if settings.IP_REPUTATION_AUTO_INCIDENT_ENABLED and result["overall_verdict"] == "malicious":
        await create_or_update_candidate(db, normalized_ip, result)
    await db.commit()
    return {"success": True, "cached": False, "ip": normalized_ip, "reputation": reputation_to_dict(row, include_raw=False), "error": None}


async def save_reputation_result(db: AsyncSession, result: dict):
    row = (await db.execute(text("""
        INSERT INTO ip_reputation (
            ip_address, is_public, overall_score, overall_verdict,
            abuseipdb_score, abuseipdb_total_reports, abuseipdb_country_code, abuseipdb_usage_type,
            abuseipdb_isp, abuseipdb_domain, abuseipdb_last_reported_at,
            virustotal_malicious, virustotal_suspicious, virustotal_harmless, virustotal_undetected,
            virustotal_reputation, virustotal_country, virustotal_as_owner, virustotal_network,
            provider_sources, raw_abuseipdb, raw_virustotal, last_seen_at, last_checked_at, expires_at, error_message
        )
        VALUES (
            :ip_address, :is_public, :overall_score, :overall_verdict,
            :abuseipdb_score, :abuseipdb_total_reports, :abuseipdb_country_code, :abuseipdb_usage_type,
            :abuseipdb_isp, :abuseipdb_domain, :abuseipdb_last_reported_at,
            :virustotal_malicious, :virustotal_suspicious, :virustotal_harmless, :virustotal_undetected,
            :virustotal_reputation, :virustotal_country, :virustotal_as_owner, :virustotal_network,
            :provider_sources, :raw_abuseipdb, :raw_virustotal, NOW(), :last_checked_at, :expires_at, :error_message
        )
        ON CONFLICT (ip_address) DO UPDATE SET
            is_public = EXCLUDED.is_public,
            overall_score = EXCLUDED.overall_score,
            overall_verdict = EXCLUDED.overall_verdict,
            abuseipdb_score = EXCLUDED.abuseipdb_score,
            abuseipdb_total_reports = EXCLUDED.abuseipdb_total_reports,
            abuseipdb_country_code = EXCLUDED.abuseipdb_country_code,
            abuseipdb_usage_type = EXCLUDED.abuseipdb_usage_type,
            abuseipdb_isp = EXCLUDED.abuseipdb_isp,
            abuseipdb_domain = EXCLUDED.abuseipdb_domain,
            abuseipdb_last_reported_at = EXCLUDED.abuseipdb_last_reported_at,
            virustotal_malicious = EXCLUDED.virustotal_malicious,
            virustotal_suspicious = EXCLUDED.virustotal_suspicious,
            virustotal_harmless = EXCLUDED.virustotal_harmless,
            virustotal_undetected = EXCLUDED.virustotal_undetected,
            virustotal_reputation = EXCLUDED.virustotal_reputation,
            virustotal_country = EXCLUDED.virustotal_country,
            virustotal_as_owner = EXCLUDED.virustotal_as_owner,
            virustotal_network = EXCLUDED.virustotal_network,
            provider_sources = EXCLUDED.provider_sources,
            raw_abuseipdb = EXCLUDED.raw_abuseipdb,
            raw_virustotal = EXCLUDED.raw_virustotal,
            last_seen_at = NOW(),
            last_checked_at = EXCLUDED.last_checked_at,
            expires_at = EXCLUDED.expires_at,
            error_message = EXCLUDED.error_message
        RETURNING *
    """).bindparams(
        bindparam("provider_sources", type_=JSONB),
        bindparam("raw_abuseipdb", type_=JSONB),
        bindparam("raw_virustotal", type_=JSONB),
    ), result)).mappings().first()
    return row


async def link_incident_reputation(db: AsyncSession, incident_id: str, ip: str, reputation_id: str, result: dict) -> None:
    await db.execute(text("""
        INSERT INTO incident_ip_reputation_links (incident_id, ip_address, reputation_id, verdict, score, source_tools)
        VALUES (:incident_id, :ip, :reputation_id, :verdict, :score, :source_tools)
        ON CONFLICT (incident_id, ip_address) DO UPDATE
        SET reputation_id = EXCLUDED.reputation_id,
            verdict = EXCLUDED.verdict,
            score = EXCLUDED.score,
            source_tools = EXCLUDED.source_tools
    """).bindparams(bindparam("source_tools", type_=JSONB)), {
        "incident_id": incident_id,
        "ip": ip,
        "reputation_id": reputation_id,
        "verdict": result["overall_verdict"],
        "score": result["overall_score"],
        "source_tools": result.get("source_tools") or [],
    })


async def create_or_update_candidate(db: AsyncSession, ip: str, result: dict) -> None:
    bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    dedup_key = hashlib.sha256(f"ip-reputation|{ip}|{bucket}|{result['overall_verdict']}".encode()).hexdigest()
    existing = (await db.execute(text("""
        SELECT id FROM incidents
        WHERE dedup_key = :dedup_key
           OR (source = 'IP Reputation' AND status NOT IN ('closed','resolved','rejected') AND entities->>'source_ip' = :ip)
        ORDER BY created_at DESC
        LIMIT 1
    """), {"dedup_key": dedup_key, "ip": ip})).scalar()
    desc = (
        f"Public IP {ip} was classified as {result['overall_verdict']} by IP reputation enrichment. "
        f"AbuseIPDB score={result.get('abuseipdb_score')}, reports={result.get('abuseipdb_total_reports')}; "
        f"VirusTotal malicious={result.get('virustotal_malicious')}, suspicious={result.get('virustotal_suspicious')}."
    )
    if existing:
        await db.execute(text("""
            UPDATE incidents
            SET occurrence_count = occurrence_count + 1,
                last_seen = NOW(),
                description = COALESCE(description, :description),
                updated_at = NOW()
            WHERE id = :id
        """), {"id": str(existing), "description": desc})
        return
    severity = 4 if result["overall_verdict"] == "malicious" else 3
    await db.execute(text("""
        INSERT INTO incidents (
            title, description, severity, status, activation_state, is_active,
            category, source, detection_source, entities, dedup_key, approval_status,
            analyst_verdict, priority, workflow_status, first_seen, last_seen, updated_at
        )
        VALUES (
            :title, :description, :severity, 'pending_approval', 'pending_evidence', FALSE,
            'network', 'IP Reputation', 'ip_reputation', :entities, :dedup_key, 'pending',
            'needs_more_evidence', :priority, 'open', NOW(), NOW(), NOW()
        )
    """).bindparams(bindparam("entities", type_=JSONB)), {
        "title": f"Malicious IP observed: {ip}",
        "description": desc,
        "severity": severity,
        "entities": {"source_ip": ip, "ip_reputation": result["provider_sources"]},
        "dedup_key": dedup_key,
        "priority": "high" if severity >= 4 else "medium",
    })


async def incident_ip_reputation(db: AsyncSession, incident_id: str, include_raw: bool = False) -> dict:
    await extract_and_queue_incident_ips(db, incident_id)
    rows = (await db.execute(text("""
        SELECT r.*
        FROM incident_ip_reputation_links l
        JOIN ip_reputation r ON r.id = l.reputation_id
        WHERE l.incident_id = :incident_id
        ORDER BY r.overall_score DESC, r.ip_address ASC
    """), {"incident_id": incident_id})).mappings().all()
    return {"success": True, "incident_id": incident_id, "reputations": [reputation_to_dict(row, include_raw=include_raw) for row in rows], "error": None}


async def extract_and_queue_incident_ips(db: AsyncSession, incident_id: str) -> dict:
    evidence = (await db.execute(text("""
        SELECT id, source_system, event_hash, source_ip, destination_ip, raw_event, raw_data
        FROM evidence
        WHERE incident_id = :incident_id
        LIMIT 500
    """), {"incident_id": incident_id})).mappings().all()
    incident = (await db.execute(text("SELECT entities FROM incidents WHERE id = :incident_id"), {"incident_id": incident_id})).mappings().first()
    events = [dict(row) for row in evidence]
    if incident and incident.get("entities"):
        events.append(incident["entities"])
    ips, skipped = extract_unique_public_ips(events)
    for row in evidence:
        for field in ("source_ip", "destination_ip"):
            value = row.get(field)
            if value and is_public_ip(str(value)):
                await upsert_observation(
                    db,
                    str(ipaddress.ip_address(str(value))),
                    source_system=row.get("source_system") or "evidence",
                    incident_id=incident_id,
                    evidence_id=str(row.get("id")),
                    event_hash=row.get("event_hash"),
                    field_name=field,
                )
    result = await enqueue_or_cache_ips(db, ips, incident_id=incident_id, source_system="incident")
    result["skipped_private"] += skipped
    return result


async def observations_for_ip(db: AsyncSession, ip: str) -> dict:
    rows = (await db.execute(text("""
        SELECT o.*, i.title AS incident_title
        FROM ip_observations o
        LEFT JOIN incidents i ON i.id = o.incident_id
        WHERE o.ip_address = :ip
        ORDER BY o.last_seen_at DESC
        LIMIT 200
    """), {"ip": ip})).mappings().all()
    return {
        "success": True,
        "ip": ip,
        "observations": [
            {
                "id": str(row["id"]),
                "ip_address": row["ip_address"],
                "source_system": row["source_system"],
                "incident_id": str(row["incident_id"]) if row.get("incident_id") else None,
                "incident_title": row.get("incident_title"),
                "evidence_id": str(row["evidence_id"]) if row.get("evidence_id") else None,
                "field_name": row.get("field_name"),
                "occurrence_count": int(row.get("occurrence_count") or 0),
                "first_seen_at": row["first_seen_at"].isoformat() if row.get("first_seen_at") else None,
                "last_seen_at": row["last_seen_at"].isoformat() if row.get("last_seen_at") else None,
            }
            for row in rows
        ],
        "error": None,
    }


def provider_status() -> dict:
    if is_demo_mode():
        return demo_provider_status()
    settings = get_settings()
    return {
        "success": True,
        "enabled": bool(settings.IP_REPUTATION_ENABLED),
        "abuseipdb": {"configured": bool(settings.ABUSEIPDB_API_KEY), "connected": None, "error": None if settings.ABUSEIPDB_API_KEY else "Not configured"},
        "virustotal": {"configured": bool(settings.VIRUSTOTAL_API_KEY), "connected": None, "error": None if settings.VIRUSTOTAL_API_KEY else "Not configured"},
        "full_reputation_available": bool(settings.ABUSEIPDB_API_KEY and settings.VIRUSTOTAL_API_KEY),
        "error": None,
    }
