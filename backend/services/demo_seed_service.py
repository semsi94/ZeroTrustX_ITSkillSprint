from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import hash_password
from services.demo_mode import (
    DEMO_DEFAULT_PASSWORDS,
    DEMO_USERS,
    demo_catalog,
    demo_password_for_setting,
    demo_uuid,
    incident_demo_payload,
)
from services.mitre_mapping_service import ensure_attack_data


def _as_dt(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _json_stmt(sql: str, *json_keys: str):
    stmt = text(sql)
    for key in json_keys:
        stmt = stmt.bindparams(bindparam(key, type_=JSONB))
    return stmt


async def ensure_demo_users(db: AsyncSession) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    mapping: dict[str, str] = {}
    password_keys = {
        "admin": "SEED_ADMIN_PASSWORD",
        "analyst": "SEED_ANALYST_PASSWORD",
        "viewer": "SEED_VIEWER_PASSWORD",
    }
    for row in DEMO_USERS:
        password_key = password_keys[row["username"]]
        password = demo_password_for_setting(password_key) or DEMO_DEFAULT_PASSWORDS[password_key]
        password_hash = hash_password(password)
        existing = (await db.execute(text("""
            SELECT id FROM users
            WHERE lower(username) = lower(:username)
               OR lower(email) = lower(:email)
            LIMIT 1
        """), {"username": row["username"], "email": row["email"]})).scalar()
        if existing:
            await db.execute(text("""
                UPDATE users
                SET username = :username,
                    email = :email,
                    display_name = :display_name,
                    role = :role,
                    password_hash = :password_hash,
                    is_active = TRUE,
                    disabled = FALSE,
                    mfa_enabled = :mfa_enabled,
                    mfa_enrolled_at = CASE WHEN :mfa_enabled THEN COALESCE(mfa_enrolled_at, NOW() - INTERVAL '45 days') ELSE NULL END,
                    last_mfa_at = CASE WHEN :mfa_enabled THEN NOW() - INTERVAL '2 hours' ELSE NULL END,
                    last_login_at = :last_login_at,
                    last_login_ip = :last_login_ip,
                    last_login_country = :last_login_country,
                    updated_at = NOW()
                WHERE id = :id
            """), {
                "id": str(existing),
                "username": row["username"],
                "email": row["email"],
                "display_name": row["display_name"],
                "role": row["role"],
                "password_hash": password_hash,
                "mfa_enabled": row["mfa_enabled"],
                "last_login_at": now - timedelta(minutes=20 if row["username"] == "admin" else 75),
                "last_login_ip": row["last_login_ip"],
                "last_login_country": row["last_login_country"],
            })
            mapping[row["username"]] = str(existing)
        else:
            inserted = (await db.execute(text("""
                INSERT INTO users (
                    id, username, email, display_name, password_hash, role,
                    is_active, disabled, mfa_enabled, mfa_enrolled_at, last_mfa_at,
                    last_login_at, last_login_ip, last_login_country
                )
                VALUES (
                    :id, :username, :email, :display_name, :password_hash, :role,
                    TRUE, FALSE, :mfa_enabled, :mfa_enrolled_at, :last_mfa_at,
                    :last_login_at, :last_login_ip, :last_login_country
                )
                RETURNING id
            """), {
                "id": demo_uuid("user", row["username"]),
                "username": row["username"],
                "email": row["email"],
                "display_name": row["display_name"],
                "password_hash": password_hash,
                "role": row["role"],
                "mfa_enabled": row["mfa_enabled"],
                "mfa_enrolled_at": now - timedelta(days=45) if row["mfa_enabled"] else None,
                "last_mfa_at": now - timedelta(hours=2) if row["mfa_enabled"] else None,
                "last_login_at": now - timedelta(minutes=20 if row["username"] == "admin" else 75),
                "last_login_ip": row["last_login_ip"],
                "last_login_country": row["last_login_country"],
            })).scalar_one()
            mapping[row["username"]] = str(inserted)

    for username, user_id in mapping.items():
        await db.execute(text("""
            INSERT INTO user_preferences (
                user_id,
                email_notifications_enabled,
                incident_notifications_enabled,
                alert_notifications_enabled,
                weekly_report_enabled,
                theme,
                table_density,
                default_time_range,
                default_page_size
            )
            VALUES (
                :user_id,
                TRUE,
                TRUE,
                TRUE,
                CASE WHEN :username = 'viewer' THEN FALSE ELSE TRUE END,
                'dark',
                'comfortable',
                'Last 24h',
                100
            )
            ON CONFLICT (user_id) DO UPDATE
            SET email_notifications_enabled = EXCLUDED.email_notifications_enabled,
                incident_notifications_enabled = EXCLUDED.incident_notifications_enabled,
                alert_notifications_enabled = EXCLUDED.alert_notifications_enabled,
                weekly_report_enabled = EXCLUDED.weekly_report_enabled,
                theme = EXCLUDED.theme,
                table_density = EXCLUDED.table_density,
                default_time_range = EXCLUDED.default_time_range,
                default_page_size = EXCLUDED.default_page_size,
                updated_at = NOW()
        """), {"user_id": user_id, "username": username})
    return mapping


async def _clear_demo_rows(db: AsyncSession) -> None:
    catalog = demo_catalog()
    scenario_rows = catalog["scenarios"]
    incident_ids = [scenario["id"] for scenario in scenario_rows]
    asset_ids = [demo_uuid("asset", asset["slug"]) for asset in catalog["assets"]]
    alert_ids = [demo_uuid("db-alert", scenario["slug"], idx) for scenario in scenario_rows for idx in range(1, 3)]
    evidence_ids = [demo_uuid("evidence", scenario["slug"], event["id"]) for scenario in scenario_rows for event in scenario["events"]]
    observable_ids = [demo_uuid("observable", scenario["slug"], idx) for scenario in scenario_rows for idx in range(1, 5)]
    comment_ids = [demo_uuid("comment", scenario["slug"], idx) for scenario in scenario_rows for idx in range(1, 3)]
    activity_ids = [demo_uuid("activity", scenario["slug"], idx) for scenario in scenario_rows for idx in range(1, 7)]
    mitre_ids = [demo_uuid("mitre-link", scenario["slug"], idx) for scenario in scenario_rows for idx, _ in enumerate(scenario["mitre"], start=1)]
    response_action_ids = [demo_uuid("response-action", scenario["slug"], idx) for scenario in scenario_rows for idx, _ in enumerate(scenario["response_actions"], start=1)]
    containment_ids = [demo_uuid("containment", scenario["slug"], idx) for scenario in scenario_rows for idx, _ in enumerate(scenario["response_actions"], start=1)]
    external_alert_ids = [demo_uuid("external-alert", scenario["slug"]) for scenario in scenario_rows]
    reputation_ids = [row["id"] for row in catalog["reputation"].values()]
    background_observation_ids = [demo_uuid("observation", "background", ip) for ip in catalog["reputation"].keys()]
    incident_reputation_ids = [
        demo_uuid("incident-reputation", scenario["slug"], ip, field)
        for scenario in scenario_rows
        for field, ip in (("source_ip", scenario["source_ip"]), ("destination_ip", scenario["destination_ip"]))
        if ip and "." in ip and not ip.startswith("10.")
    ]
    observation_ids = [
        demo_uuid("observation", scenario["slug"], ip, field)
        for scenario in scenario_rows
        for field, ip in (("source_ip", scenario["source_ip"]), ("destination_ip", scenario["destination_ip"]))
        if ip and "." in ip and not ip.startswith("10.")
    ] + background_observation_ids

    delete_specs = [
        ("incident_ip_reputation_links", incident_reputation_ids),
        ("ip_observations", observation_ids),
        ("external_alerts", external_alert_ids),
        ("containment_actions", containment_ids),
        ("response_actions", response_action_ids),
        ("incident_mitre_links", mitre_ids),
        ("incident_activity", activity_ids),
        ("incident_comments", comment_ids),
        ("observables", observable_ids),
        ("evidence", evidence_ids),
        ("alerts", alert_ids),
        ("incidents", incident_ids),
        ("assets", asset_ids),
        ("ip_reputation", reputation_ids),
    ]
    for table_name, ids in delete_specs:
        if not ids:
            continue
        await db.execute(
            text(f"DELETE FROM {table_name} WHERE id = ANY(:ids)").bindparams(bindparam("ids", type_=ARRAY(PG_UUID(as_uuid=False)))),
            {"ids": ids},
        )

    await db.execute(text("""
        DELETE FROM containment_actions
        WHERE incident_id = ANY(:incident_ids)
    """).bindparams(bindparam("incident_ids", type_=ARRAY(PG_UUID(as_uuid=False)))), {"incident_ids": incident_ids})
    await db.execute(text("""
        DELETE FROM response_actions
        WHERE incident_id = ANY(:incident_ids)
    """).bindparams(bindparam("incident_ids", type_=ARRAY(PG_UUID(as_uuid=False)))), {"incident_ids": incident_ids})
    await db.execute(text("""
        DELETE FROM incident_ip_reputation_links
        WHERE incident_id = ANY(:incident_ids)
    """).bindparams(bindparam("incident_ids", type_=ARRAY(PG_UUID(as_uuid=False)))), {"incident_ids": incident_ids})
    await db.execute(text("""
        DELETE FROM ip_observations
        WHERE incident_id = ANY(:incident_ids) OR evidence_id = ANY(:evidence_ids)
    """).bindparams(
        bindparam("incident_ids", type_=ARRAY(PG_UUID(as_uuid=False))),
        bindparam("evidence_ids", type_=ARRAY(PG_UUID(as_uuid=False))),
    ), {"incident_ids": incident_ids, "evidence_ids": evidence_ids})


async def reset_demo_data(db: AsyncSession) -> dict:
    await _clear_demo_rows(db)
    await db.commit()
    return {"success": True, "reset": True, "demo_mode": True, "error": None}


async def _ensure_attack_data_for_demo(db: AsyncSession) -> dict:
    try:
        await ensure_attack_data(db)
        return {"success": True, "startup_safe": True}
    except Exception as exc:
        return {"success": False, "startup_safe": True, "error": str(exc)}


async def seed_demo_data(db: AsyncSession, *, reset_first: bool = False) -> dict:
    catalog = demo_catalog()
    if reset_first:
        await _clear_demo_rows(db)
    user_ids = await ensure_demo_users(db)
    existing_seeded = 0
    if catalog["scenarios"]:
        existing_seeded = int((await db.execute(text("""
            SELECT COUNT(*) FROM incidents WHERE id = :id
        """), {"id": catalog["scenarios"][0]["id"]})).scalar() or 0)
    if existing_seeded and not reset_first:
        await db.commit()
        return {
            "success": True,
            "demo_mode": True,
            "seeded": False,
            "skipped": True,
            "reason": "Demo data already seeded. Use reset/reseed to rebuild the corpus.",
            "users": len(user_ids),
            "assets": len(catalog["assets"]),
            "incidents": len(catalog["scenarios"]),
            "events": len(catalog["events"]),
            "saved_searches": len(catalog["saved_searches"]),
            "fired_alerts": len(catalog["fired_alerts"]),
            "reputation_rows": len(catalog["reputation"]),
            "error": None,
        }
    mitre_result = await _ensure_attack_data_for_demo(db)

    for asset in catalog["assets"]:
        await db.execute(text("""
            INSERT INTO assets (id, hostname, ip, zone, owner, asset_criticality, is_placeholder, created_at, updated_at)
            VALUES (:id, :hostname, :ip, :zone, :owner, :asset_criticality, FALSE, NOW() - INTERVAL '90 days', NOW())
            ON CONFLICT (id) DO UPDATE
            SET hostname = EXCLUDED.hostname,
                ip = EXCLUDED.ip,
                zone = EXCLUDED.zone,
                owner = EXCLUDED.owner,
                asset_criticality = EXCLUDED.asset_criticality,
                is_placeholder = FALSE,
                updated_at = NOW()
        """), {
            "id": demo_uuid("asset", asset["slug"]),
            "hostname": asset["hostname"],
            "ip": asset["ip"],
            "zone": asset["zone"],
            "owner": asset["owner"],
            "asset_criticality": asset["asset_criticality"],
        })

    for reputation in catalog["reputation"].values():
        await db.execute(_json_stmt("""
            INSERT INTO ip_reputation (
                id, ip_address, is_public, overall_score, overall_verdict,
                abuseipdb_score, abuseipdb_total_reports, abuseipdb_country_code, abuseipdb_usage_type,
                abuseipdb_isp, abuseipdb_domain, abuseipdb_last_reported_at, virustotal_malicious,
                virustotal_suspicious, virustotal_harmless, virustotal_undetected, virustotal_reputation,
                virustotal_country, virustotal_as_owner, virustotal_network, provider_sources,
                raw_abuseipdb, raw_virustotal, first_seen_at, last_seen_at, last_checked_at, expires_at, error_message
            )
            VALUES (
                :id, :ip_address, :is_public, :overall_score, :overall_verdict,
                :abuseipdb_score, :abuseipdb_total_reports, :abuseipdb_country_code, :abuseipdb_usage_type,
                :abuseipdb_isp, :abuseipdb_domain, :abuseipdb_last_reported_at, :virustotal_malicious,
                :virustotal_suspicious, :virustotal_harmless, :virustotal_undetected, :virustotal_reputation,
                :virustotal_country, :virustotal_as_owner, :virustotal_network, :provider_sources,
                :raw_abuseipdb, :raw_virustotal, :first_seen_at, :last_seen_at, :last_checked_at, :expires_at, :error_message
            )
            ON CONFLICT (ip_address) DO UPDATE
            SET is_public = EXCLUDED.is_public,
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
                first_seen_at = EXCLUDED.first_seen_at,
                last_seen_at = EXCLUDED.last_seen_at,
                last_checked_at = EXCLUDED.last_checked_at,
                expires_at = EXCLUDED.expires_at,
                error_message = EXCLUDED.error_message
        """, "provider_sources", "raw_abuseipdb", "raw_virustotal"), reputation)

    for scenario in catalog["scenarios"]:
        primary_asset_id = demo_uuid("asset", scenario["asset"]["slug"])
        first_mitre = scenario["mitre"][0] if scenario["mitre"] else None
        entities = {
            **incident_demo_payload(scenario["id"])["events"][0]["raw_data"],
            **{
                "demo_mode": True,
                "scenario": scenario["slug"],
                "source_ip": scenario["source_ip"],
                "destination_ip": scenario["destination_ip"],
                "user": scenario["user"],
                "host": scenario["asset"]["hostname"],
                "trigger_time": scenario["alert_time"].isoformat(),
                "saved_search_name": scenario["saved_search_name"],
                "query": scenario["search"],
                "result_count": scenario["result_count"],
            },
        }
        tags = ["demo_mode", scenario["slug"], scenario["category"], scenario["priority"]]
        source_hash = hashlib.sha256(f"demo|incident|{scenario['slug']}".encode("utf-8")).hexdigest()
        await db.execute(_json_stmt("""
            INSERT INTO incidents (
                id, title, description, severity, confidence, status, activation_state,
                is_active, evidence_count, category, source, owner, linked_splunk_alert_id,
                detection_source, entities, tags, notes, approval_status, approved_by, approved_at,
                source_ref, source_hash, dedup_key, occurrence_count, analyst_verdict, verdict_reason,
                verdict_by, verdict_at, cia_c, cia_i, cia_a, mitre_tactic, mitre_technique,
                mitre_technique_id, mitre_technique_name, mitre_confidence, mitre_mapping_source,
                primary_asset_id, response_level, source_systems, priority_score, priority, queue,
                workflow_status, sla_due_at, first_ack_due_at, resolve_due_at, escalation_level,
                requested_action, resolution_notes, close_reason, is_false_positive, first_seen,
                last_seen, triaged_at, contained_at, closed_at, analyst_notes, created_at, updated_at
            )
            VALUES (
                :id, :title, :description, :severity, :confidence, :status, :activation_state,
                :is_active, :evidence_count, :category, :source, :owner, :linked_splunk_alert_id,
                :detection_source, :entities, :tags, :notes, :approval_status, :approved_by, :approved_at,
                :source_ref, :source_hash, :dedup_key, :occurrence_count, :analyst_verdict, :verdict_reason,
                :verdict_by, :verdict_at, :cia_c, :cia_i, :cia_a, :mitre_tactic, :mitre_technique,
                :mitre_technique_id, :mitre_technique_name, :mitre_confidence, :mitre_mapping_source,
                :primary_asset_id, :response_level, :source_systems, :priority_score, :priority, :queue,
                :workflow_status, :sla_due_at, :first_ack_due_at, :resolve_due_at, :escalation_level,
                :requested_action, :resolution_notes, :close_reason, :is_false_positive, :first_seen,
                :last_seen, :triaged_at, :contained_at, :closed_at, :analyst_notes, :created_at, :updated_at
            )
        """, "entities"), {
            "id": scenario["id"],
            "title": scenario["title"],
            "description": scenario["description"],
            "severity": {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(scenario["severity"], 3),
            "confidence": scenario["confidence"],
            "status": scenario["status"],
            "activation_state": scenario["activation_state"],
            "is_active": scenario["is_active"],
            "evidence_count": len(scenario["events"]),
            "category": scenario["category"],
            "source": scenario["source"],
            "owner": scenario["owner"],
            "linked_splunk_alert_id": scenario["alert_id"],
            "detection_source": scenario["detection_source"],
            "entities": entities,
            "tags": tags,
            "notes": scenario["notes"],
            "approval_status": scenario["approval_status"],
            "approved_by": "Aysel Mammadova" if scenario["approval_status"] == "approved" else None,
            "approved_at": scenario["started_at"] + timedelta(minutes=12) if scenario["approval_status"] == "approved" else None,
            "source_ref": scenario["alert_id"],
            "source_hash": source_hash,
            "dedup_key": hashlib.sha256(f"demo|dedup|{scenario['slug']}".encode("utf-8")).hexdigest(),
            "occurrence_count": max(1, scenario["result_count"] // 2),
            "analyst_verdict": scenario["analyst_verdict"],
            "verdict_reason": scenario["description"],
            "verdict_by": scenario["verdict_by"],
            "verdict_at": scenario["closed_at"] or scenario["last_seen"],
            "cia_c": scenario["cia"][0],
            "cia_i": scenario["cia"][1],
            "cia_a": scenario["cia"][2],
            "mitre_tactic": first_mitre.tactic_id if first_mitre else None,
            "mitre_technique": first_mitre.technique_name if first_mitre else None,
            "mitre_technique_id": first_mitre.technique_id if first_mitre else None,
            "mitre_technique_name": first_mitre.technique_name if first_mitre else None,
            "mitre_confidence": (first_mitre.confidence_score / 100) if first_mitre else None,
            "mitre_mapping_source": "auto",
            "primary_asset_id": primary_asset_id,
            "response_level": scenario["response_level"],
            "source_systems": scenario["source_systems"],
            "priority_score": scenario["response_level"] * 25 + int(scenario["confidence"] * 50),
            "priority": scenario["priority"],
            "queue": scenario["queue"],
            "workflow_status": scenario["workflow_status"],
            "sla_due_at": scenario["first_seen"] + timedelta(hours=12),
            "first_ack_due_at": scenario["first_seen"] + timedelta(hours=1),
            "resolve_due_at": scenario["first_seen"] + timedelta(hours=36),
            "escalation_level": 1 if scenario["severity"] in {"high", "critical"} else 0,
            "requested_action": "Validate scope, confirm affected entities, and execute containment where appropriate.",
            "resolution_notes": scenario["resolution_notes"],
            "close_reason": scenario["close_reason"],
            "is_false_positive": scenario["analyst_verdict"] == "false_positive",
            "first_seen": scenario["first_seen"],
            "last_seen": scenario["last_seen"],
            "triaged_at": scenario["triaged_at"],
            "contained_at": scenario["contained_at"],
            "closed_at": scenario["closed_at"],
            "analyst_notes": scenario["notes"],
            "created_at": scenario["first_seen"],
            "updated_at": scenario["last_seen"] + timedelta(minutes=18),
        })

        alert_events = list(scenario["events"][:2]) if len(scenario["events"]) >= 2 else list(scenario["events"])
        while len(alert_events) < 2:
            alert_events.append(scenario["events"][-1])
        for idx, event in enumerate(alert_events, start=1):
            await db.execute(_json_stmt("""
                INSERT INTO alerts (
                    id, incident_id, source_system, event_type, src_ip, dest_ip, username,
                    hostname, signature, category, zone, severity, confidence, cia_c, cia_i,
                    cia_a, mitre_tactic, raw_ref, raw_payload, event_time, created_at
                )
                VALUES (
                    :id, :incident_id, :source_system, :event_type, :src_ip, :dest_ip, :username,
                    :hostname, :signature, :category, :zone, :severity, :confidence, :cia_c, :cia_i,
                    :cia_a, :mitre_tactic, :raw_ref, :raw_payload, :event_time, :created_at
                )
            """, "raw_payload"), {
                "id": demo_uuid("db-alert", scenario["slug"], idx),
                "incident_id": scenario["id"],
                "source_system": event["source_system"],
                "event_type": event["event_category"],
                "src_ip": scenario["source_ip"],
                "dest_ip": scenario["destination_ip"],
                "username": scenario["user"],
                "hostname": scenario["asset"]["hostname"],
                "signature": event["signature"],
                "category": scenario["category"],
                "zone": scenario["asset"]["zone"],
                "severity": {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(event["severity"], 3),
                "confidence": scenario["confidence"],
                "cia_c": scenario["cia"][0],
                "cia_i": scenario["cia"][1],
                "cia_a": scenario["cia"][2],
                "mitre_tactic": scenario["mitre"][0].tactic_id if scenario["mitre"] else None,
                "raw_ref": scenario["alert_id"],
                "raw_payload": event["raw_event"],
                "event_time": _as_dt(event["time"]),
                "created_at": _as_dt(event["time"]),
            })

        for event in scenario["events"]:
            evidence_id = demo_uuid("evidence", scenario["slug"], event["id"])
            event_hash = hashlib.sha256(f"{scenario['slug']}|{event['id']}".encode("utf-8")).hexdigest()
            await db.execute(_json_stmt("""
                INSERT INTO evidence (
                    id, incident_id, type, path_or_ref, hash, event_hash, event_time, source,
                    source_system, source_ref, query_sid, search_id, content_hash, "index",
                    sourcetype, host, source_ip, destination_ip, user_email, action, message,
                    collected_by, collector_id, collected_at, raw_data, raw_event
                )
                VALUES (
                    :id, :incident_id, 'log', :path_or_ref, :hash, :event_hash, :event_time, :source,
                    :source_system, :source_ref, :query_sid, :search_id, :content_hash, :index,
                    :sourcetype, :host, :source_ip, :destination_ip, :user_email, :action, :message,
                    :collected_by, :collector_id, :collected_at, :raw_data, :raw_event
                )
            """, "raw_data", "raw_event"), {
                "id": evidence_id,
                "incident_id": scenario["id"],
                "path_or_ref": f"splunk://{event['index']}/{event['query_sid']}",
                "hash": event_hash[:64],
                "event_hash": event_hash,
                "event_time": _as_dt(event["time"]),
                "source": event["source_system"],
                "source_system": event["source_system"],
                "source_ref": scenario["alert_id"],
                "query_sid": event["query_sid"],
                "search_id": event["search_id"],
                "content_hash": hashlib.sha256(event["raw"].encode("utf-8")).hexdigest(),
                "index": event["index"],
                "sourcetype": event["sourcetype"],
                "host": event["host"],
                "source_ip": event["source_ip"],
                "destination_ip": event["destination_ip"],
                "user_email": event["user"],
                "action": event["action"],
                "message": event["message"],
                "collected_by": "demo_pipeline",
                "collector_id": "demo-mode",
                "collected_at": _as_dt(event["time"]),
                "raw_data": event["raw_data"],
                "raw_event": event["raw_event"],
            })

        observable_rows = [
            ("ip", scenario["source_ip"], True),
            ("ip", scenario["destination_ip"], False),
            ("host", scenario["asset"]["hostname"], False),
            ("user", scenario["user"], False),
        ]
        for idx, (obs_type, obs_value, is_ioc) in enumerate(observable_rows, start=1):
            if not obs_value:
                continue
            await db.execute(text("""
                INSERT INTO observables (id, incident_id, type, value, is_ioc, is_sighted, first_seen_at)
                VALUES (:id, :incident_id, :type, :value, :is_ioc, TRUE, :first_seen_at)
            """), {
                "id": demo_uuid("observable", scenario["slug"], idx),
                "incident_id": scenario["id"],
                "type": obs_type,
                "value": obs_value,
                "is_ioc": is_ioc,
                "first_seen_at": scenario["first_seen"],
            })

        for idx, (comment_type, body) in enumerate(scenario["comments"], start=1):
            await db.execute(text("""
                INSERT INTO incident_comments (id, incident_id, body, comment_type, created_by, created_at)
                VALUES (:id, :incident_id, :body, :comment_type, :created_by, :created_at)
            """), {
                "id": demo_uuid("comment", scenario["slug"], idx),
                "incident_id": scenario["id"],
                "body": body,
                "comment_type": comment_type,
                "created_by": scenario["owner"],
                "created_at": scenario["first_seen"] + timedelta(minutes=20 + idx * 9),
            })

        activity_rows = [
            ("incident_created", "Incident created from correlated telemetry", scenario["first_seen"], {"source": scenario["source"]}),
            ("evidence_attached", f"{len(scenario['events'])} evidence events attached", scenario["first_seen"] + timedelta(minutes=6), {"evidence_count": len(scenario["events"])}),
            ("mitre_mapped", f"Mapped {len(scenario['mitre'])} MITRE techniques", scenario["first_seen"] + timedelta(minutes=11), {"techniques": [item.technique_id for item in scenario["mitre"]]}),
            ("owner_assigned", f"Assigned to {scenario['owner']}", scenario["first_seen"] + timedelta(minutes=16), {"owner": scenario["owner"]}),
        ]
        if scenario["response_actions"]:
            activity_rows.append(("response_action_requested", f"{scenario['response_actions'][0]['action_type']} requested", scenario["first_seen"] + timedelta(minutes=24), {"target": scenario["response_actions"][0]["target"]}))
        if scenario["closed_at"]:
            activity_rows.append(("incident_closed", "Incident workflow closed", scenario["closed_at"], {"status": scenario["status"]}))
        for idx, (activity_type, summary, created_at, metadata) in enumerate(activity_rows, start=1):
            await db.execute(_json_stmt("""
                INSERT INTO incident_activity (id, incident_id, activity_type, summary, actor, metadata_json, created_at)
                VALUES (:id, :incident_id, :activity_type, :summary, :actor, :metadata, :created_at)
            """, "metadata"), {
                "id": demo_uuid("activity", scenario["slug"], idx),
                "incident_id": scenario["id"],
                "activity_type": activity_type,
                "summary": summary,
                "actor": scenario["owner"],
                "metadata": metadata,
                "created_at": created_at,
            })

        for idx, mitre in enumerate(scenario["mitre"], start=1):
            await db.execute(_json_stmt("""
                INSERT INTO incident_mitre_links (
                    id, incident_id, tactic_id, technique_id, subtechnique_id, technique_name,
                    confidence, confidence_score, mapped_by, mapping_source, reason,
                    matched_fields, matched_evidence_ids, created_by, created_at, updated_at
                )
                VALUES (
                    :id, :incident_id, :tactic_id, :technique_id, :subtechnique_id, :technique_name,
                    :confidence, :confidence_score, :mapped_by, 'auto', :reason,
                    :matched_fields, :matched_evidence_ids, :created_by, :created_at, :updated_at
                )
            """, "matched_fields", "matched_evidence_ids"), {
                "id": demo_uuid("mitre-link", scenario["slug"], idx),
                "incident_id": scenario["id"],
                "tactic_id": mitre.tactic_id,
                "technique_id": mitre.technique_id,
                "subtechnique_id": mitre.subtechnique_id,
                "technique_name": mitre.technique_name,
                "confidence": mitre.confidence_score / 100,
                "confidence_score": mitre.confidence_score,
                "mapped_by": "demo_mapping_engine",
                "reason": mitre.reason,
                "matched_fields": {
                    "saved_search_name": scenario["saved_search_name"],
                    "source_ip": scenario["source_ip"],
                    "host": scenario["asset"]["hostname"],
                },
                "matched_evidence_ids": [demo_uuid("evidence", scenario["slug"], event["id"]) for event in scenario["events"][:2]],
                "created_by": "demo_mapping_engine",
                "created_at": scenario["first_seen"] + timedelta(minutes=12),
                "updated_at": scenario["first_seen"] + timedelta(minutes=12),
            })

        for idx, action in enumerate(scenario["response_actions"], start=1):
            action_id = demo_uuid("response-action", scenario["slug"], idx)
            initiated_at = scenario["first_seen"] + timedelta(minutes=action["minutes_after"])
            executed_at = initiated_at + timedelta(minutes=2) if action["status"] == "executed" else None
            reverted_at = initiated_at + timedelta(hours=14) if action["action_type"] == "block_ip" and scenario["status"] in {"resolved", "false_positive"} else None
            await db.execute(_json_stmt("""
                INSERT INTO response_actions (
                    id, incident_id, action_type, target, alias, status, initiated_by,
                    approved_by, initiated_at, executed_at, reverted_at, output,
                    error_message, rollback_available
                )
                VALUES (
                    :id, :incident_id, :action_type, :target, :alias, :status, :initiated_by,
                    :approved_by, :initiated_at, :executed_at, :reverted_at, :output,
                    :error_message, :rollback_available
                )
            """, "output"), {
                "id": action_id,
                "incident_id": scenario["id"],
                "action_type": action["action_type"],
                "target": action["target"],
                "alias": "SOC_BLOCK_TEMP",
                "status": action["status"],
                "initiated_by": action["initiated_by"],
                "approved_by": action["approved_by"],
                "initiated_at": initiated_at,
                "executed_at": executed_at,
                "reverted_at": reverted_at,
                "output": action["output"],
                "error_message": action["error_message"],
                "rollback_available": action["rollback_available"],
            })
            await db.execute(_json_stmt("""
                INSERT INTO containment_actions (
                    id, incident_id, ticket_id, action_type, target_ip, target_type,
                    target_value, firewall, provider, alias_name, reason, requested_by,
                    approved_by, requested_at, executed_at, status, result_message, raw_response
                )
                VALUES (
                    :id, :incident_id, NULL, :action_type, :target_ip, 'ip',
                    :target_ip, 'pfSense', 'pfSense', 'SOC_BLOCK_TEMP', :reason, :requested_by,
                    :approved_by, :requested_at, :executed_at, :status, :result_message, :raw_response
                )
            """, "raw_response"), {
                "id": demo_uuid("containment", scenario["slug"], idx),
                "incident_id": scenario["id"],
                "action_type": action["action_type"],
                "target_ip": action["target"],
                "reason": f"Demo containment action for {scenario['title']}",
                "requested_by": action["initiated_by"],
                "approved_by": action["approved_by"],
                "requested_at": initiated_at,
                "executed_at": executed_at,
                "status": "success" if action["status"] == "executed" else action["status"],
                "result_message": action["output"].get("message") if isinstance(action["output"], dict) else action["status"],
                "raw_response": action["output"],
            })

        await db.execute(_json_stmt("""
            INSERT INTO external_alerts (
                id, source_system, source_event_id, rule_name, severity,
                raw_json, dedupe_key, ingested_at, linked_incident_id
            )
            VALUES (
                :id, 'splunk', :source_event_id, :rule_name, :severity,
                :raw_json, :dedupe_key, :ingested_at, :linked_incident_id
            )
        """, "raw_json"), {
            "id": demo_uuid("external-alert", scenario["slug"]),
            "source_event_id": scenario["alert_id"],
            "rule_name": scenario["saved_search_name"],
            "severity": scenario["severity"],
            "raw_json": {
                "alert_id": scenario["alert_id"],
                "saved_search_name": scenario["saved_search_name"],
                "query": scenario["search"],
                "result_count": scenario["result_count"],
                "source_ip": scenario["source_ip"],
                "destination_ip": scenario["destination_ip"],
            },
            "dedupe_key": hashlib.sha256(f"demo|external-alert|{scenario['slug']}".encode("utf-8")).hexdigest(),
            "ingested_at": scenario["alert_time"],
            "linked_incident_id": scenario["id"],
        })

        for field_name, ip_value in (("source_ip", scenario["source_ip"]), ("destination_ip", scenario["destination_ip"])):
            if not ip_value or ip_value.startswith("10."):
                continue
            reputation = catalog["reputation"].get(ip_value)
            if not reputation:
                continue
            reputation_id = (await db.execute(text("""
                SELECT id FROM ip_reputation WHERE ip_address = :ip_address LIMIT 1
            """), {"ip_address": ip_value})).scalar()
            if not reputation_id:
                continue
            link_id = demo_uuid("incident-reputation", scenario["slug"], ip_value, field_name)
            observation_id = demo_uuid("observation", scenario["slug"], ip_value, field_name)
            evidence_id = demo_uuid("evidence", scenario["slug"], scenario["events"][0]["id"])
            await db.execute(_json_stmt("""
                INSERT INTO incident_ip_reputation_links (
                    id, incident_id, ip_address, reputation_id, verdict, score, source_tools, created_at
                )
                VALUES (
                    :id, :incident_id, :ip_address, :reputation_id, :verdict, :score, :source_tools, :created_at
                )
            """, "source_tools"), {
                "id": link_id,
                "incident_id": scenario["id"],
                "ip_address": ip_value,
                "reputation_id": str(reputation_id),
                "verdict": reputation["overall_verdict"],
                "score": reputation["overall_score"],
                "source_tools": ["abuseipdb", "virustotal"],
                "created_at": scenario["first_seen"] + timedelta(minutes=5),
            })
            await db.execute(text("""
                INSERT INTO ip_observations (
                    id, ip_address, source_system, incident_id, evidence_id, event_hash,
                    field_name, first_seen_at, last_seen_at, occurrence_count
                )
                VALUES (
                    :id, :ip_address, :source_system, :incident_id, :evidence_id, :event_hash,
                    :field_name, :first_seen_at, :last_seen_at, :occurrence_count
                )
            """), {
                "id": observation_id,
                "ip_address": ip_value,
                "source_system": scenario["source_systems"][0],
                "incident_id": scenario["id"],
                "evidence_id": evidence_id,
                "event_hash": hashlib.sha256(f"{scenario['slug']}|{ip_value}|{field_name}".encode("utf-8")).hexdigest(),
                "field_name": field_name,
                "first_seen_at": scenario["first_seen"],
                "last_seen_at": scenario["last_seen"],
                "occurrence_count": max(1, len([event for event in scenario["events"] if ip_value in (event.get("source_ip"), event.get("destination_ip"))])),
            })

    for ip_value, reputation in catalog["reputation"].items():
        await db.execute(text("""
            INSERT INTO ip_observations (
                id, ip_address, source_system, incident_id, evidence_id, event_hash,
                field_name, first_seen_at, last_seen_at, occurrence_count
            )
            VALUES (
                :id, :ip_address, 'investigation', NULL, NULL, :event_hash,
                'source_ip', :first_seen_at, :last_seen_at, :occurrence_count
            )
            ON CONFLICT (id) DO UPDATE
            SET last_seen_at = EXCLUDED.last_seen_at,
                occurrence_count = EXCLUDED.occurrence_count
        """), {
            "id": demo_uuid("observation", "background", ip_value),
            "ip_address": ip_value,
            "event_hash": hashlib.sha256(f"demo|background|{ip_value}".encode("utf-8")).hexdigest(),
            "first_seen_at": reputation["first_seen_at"],
            "last_seen_at": reputation["last_seen_at"],
            "occurrence_count": 3 + int(hashlib.sha256(ip_value.encode("utf-8")).hexdigest()[:2], 16) % 18,
        })

    await db.commit()
    return {
        "success": True,
        "demo_mode": True,
        "seeded": True,
        "users": len(user_ids),
        "assets": len(catalog["assets"]),
        "incidents": len(catalog["scenarios"]),
        "events": len(catalog["events"]),
        "saved_searches": len(catalog["saved_searches"]),
        "fired_alerts": len(catalog["fired_alerts"]),
        "reputation_rows": len(catalog["reputation"]),
        "response_actions": sum(len(scenario["response_actions"]) for scenario in catalog["scenarios"]),
        "mitre_mappings": sum(len(scenario["mitre"]) for scenario in catalog["scenarios"]),
        "evidence": sum(len(scenario["events"]) for scenario in catalog["scenarios"]),
        "mitre": mitre_result,
        "error": None,
    }
