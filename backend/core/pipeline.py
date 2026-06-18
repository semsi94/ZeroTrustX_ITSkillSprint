import json
import logging
import traceback
from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from core.decision_engine import decide_response_level
from core.enricher import is_valid_ip, resolve_or_create_asset
from core.normalizer import normalize_splunk_payload
from core.risk_engine import compute_risk
from models.alert import Alert
from models.incident import Incident

log = logging.getLogger("zerotrustx.pipeline")


def _safe_ip(ip: str) -> str:
    return ip if is_valid_ip(ip) else "0.0.0.0"


async def ingest_event(payload: dict, db: AsyncSession) -> dict:
    """Ingest a single normalized security event end-to-end."""
    step_name = "init"
    try:
        step_name = "Step 1 Normalize"
        norm = normalize_splunk_payload(payload)
        log.info(
            "PIPELINE [1/8] Normalizing source=%s src=%s dest=%s sig=%s",
            norm.source_system,
            norm.src_ip,
            norm.dest_ip,
            norm.signature,
        )

        step_name = "Step 2 Enrich"
        dest_ip = _safe_ip(norm.dest_ip)
        src_ip = _safe_ip(norm.src_ip)
        asset = await resolve_or_create_asset(db, dest_ip, hostname=norm.hostname)
        log.info(
            "PIPELINE [2/8] Asset resolved hostname=%s zone=%s criticality=%s",
            asset.hostname,
            asset.zone,
            asset.asset_criticality,
        )

        step_name = "Step 3 Score"
        risk = compute_risk(
            severity=norm.severity,
            confidence=norm.confidence,
            criticality=asset.asset_criticality,
            cia_c=norm.cia_confidentiality,
            cia_i=norm.cia_integrity,
            cia_a=norm.cia_availability,
        )
        log.info(
            "PIPELINE [3/8] Score=%s severity_label=%s",
            risk.priority_score,
            risk.severity_label,
        )

        step_name = "Step 4 Correlate"
        alert_match = (
            select(Alert.id)
            .where(Alert.incident_id == Incident.id)
            .where(Alert.src_ip == src_ip)
            .exists()
        )
        correlate_stmt = (
            select(
                Incident.id,
                Incident.source_systems,
                Incident.response_level,
                Incident.severity,
                Incident.status,
            )
            .where(alert_match)
            .where(Incident.status.notin_(("closed", "false_positive")))
            .where(Incident.last_seen >= func.now() - text("INTERVAL '2 hours'"))
            .order_by(Incident.last_seen.desc())
            .limit(1)
        )
        existing = (await db.execute(correlate_stmt)).mappings().first()
        mode = "updated" if existing else "created"
        log.info("PIPELINE [4/8] Incident mode=%s", mode)

        step_name = "Step 5 Decide"
        existing_sources = list(existing["source_systems"]) if existing and existing["source_systems"] else []
        all_sources = list({*existing_sources, norm.source_system})
        level = decide_response_level(all_sources, asset.asset_criticality)
        log.info("PIPELINE [5/8] Response level=%s sources=%s", level, all_sources)

        step_name = "Step 6 Persist"
        if mode == "created":
            insert_incident = text("""
                INSERT INTO incidents
                    (title, severity, confidence, status, cia_c, cia_i, cia_a,
                     mitre_tactic, mitre_technique, primary_asset_id,
                     response_level, source_systems, priority_score,
                     is_false_positive, first_seen, last_seen)
                VALUES
                    (:title, :severity, :confidence, 'new', :cia_c, :cia_i, :cia_a,
                     :mitre_tactic, :mitre_technique, :primary_asset_id,
                     :response_level, :source_systems, :priority_score,
                     FALSE, NOW(), NOW())
                RETURNING id
            """)
            res = await db.execute(insert_incident, {
                "title": norm.signature or "Security Incident",
                "severity": risk.severity_label,
                "confidence": norm.confidence,
                "cia_c": norm.cia_confidentiality,
                "cia_i": norm.cia_integrity,
                "cia_a": norm.cia_availability,
                "mitre_tactic": norm.mitre_tactic,
                "mitre_technique": norm.mitre_technique,
                "primary_asset_id": asset.id,
                "response_level": level,
                "source_systems": [norm.source_system],
                "priority_score": risk.priority_score,
            })
            incident_id = res.scalar_one()
        else:
            incident_id = existing["id"]
            level = max(existing["response_level"] or 1, level)
            update_incident = text("""
                UPDATE incidents
                SET last_seen = NOW(),
                    source_systems = :source_systems,
                    response_level = :response_level,
                    severity = :severity,
                    priority_score = GREATEST(priority_score, :priority_score)
                WHERE id = :id
            """)
            await db.execute(update_incident, {
                "source_systems": all_sources,
                "response_level": level,
                "severity": max(existing["severity"] or 1, risk.severity_label),
                "priority_score": risk.priority_score,
                "id": incident_id,
            })

        insert_alert = text("""
            INSERT INTO alerts
                (incident_id, source_system, event_type, src_ip, dest_ip,
                 username, hostname, signature, category, zone,
                 severity, confidence, cia_c, cia_i, cia_a,
                 mitre_tactic, raw_ref, raw_payload, event_time)
            VALUES
                (:incident_id, :source_system, :event_type, :src_ip, :dest_ip,
                 :username, :hostname, :signature, :category, :zone,
                 :severity, :confidence, :cia_c, :cia_i, :cia_a,
                 :mitre_tactic, :raw_ref, CAST(:raw_payload AS JSONB), :event_time)
        """)
        await db.execute(insert_alert, {
            "incident_id": incident_id,
            "source_system": norm.source_system,
            "event_type": norm.event_type,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "username": norm.username,
            "hostname": norm.hostname,
            "signature": norm.signature,
            "category": norm.category,
            "zone": norm.zone,
            "severity": risk.severity_label,
            "confidence": norm.confidence,
            "cia_c": norm.cia_confidentiality,
            "cia_i": norm.cia_integrity,
            "cia_a": norm.cia_availability,
            "mitre_tactic": norm.mitre_tactic,
            "raw_ref": norm.raw_ref,
            "raw_payload": json.dumps(norm.raw_payload, default=str),
            "event_time": norm.event_time,
        })
        await db.commit()
        log.info("PIPELINE [6/8] DB write complete incident_id=%s", incident_id)

        step_name = "Step 7 Auto Response"
        settings = get_settings()
        pfsense_configured = all([
            settings.PFSENSE_HOST,
            settings.PFSENSE_USERNAME,
            settings.PFSENSE_PASSWORD,
        ])

        if level == 2 and pfsense_configured:
            action_insert = text("""
                INSERT INTO response_actions
                    (incident_id, action_type, target, alias, status, initiated_by, rollback_available)
                VALUES
                    (:incident_id, 'block_ip', :target, :alias, 'pending', 'auto_pipeline', TRUE)
                RETURNING id
            """)
            action_res = await db.execute(action_insert, {
                "incident_id": incident_id,
                "target": src_ip,
                "alias": settings.PFSENSE_BLOCK_ALIAS,
            })
            action_id = action_res.scalar_one()
            await db.commit()
            try:
                from workers.response_tasks import block_ip_task

                block_ip_task.delay(src_ip, str(incident_id), str(action_id), settings.PFSENSE_BLOCK_ALIAS)
            except Exception as ce:
                log.warning("PIPELINE [7/8] Celery enqueue failed: %s", ce)
            log.info("PIPELINE [7/8] Auto-block enqueued for %s", src_ip)
        elif level == 3:
            action_insert = text("""
                INSERT INTO response_actions
                    (incident_id, action_type, target, alias, status, initiated_by, rollback_available)
                VALUES
                    (:incident_id, 'hard_contain', :target, :alias, 'pending_approval', 'auto_pipeline', TRUE)
            """)
            await db.execute(action_insert, {
                "incident_id": incident_id,
                "target": src_ip,
                "alias": settings.PFSENSE_BLOCK_ALIAS,
            })
            await db.commit()
            log.info("PIPELINE [7/8] Hard containment pending approval for incident %s", incident_id)
        else:
            log.info("PIPELINE [7/8] Observe only no auto-response")

        step_name = "Step 8 Writeback"
        if settings.SPLUNK_HEC_TOKEN and settings.SPLUNK_HEC_URL:
            try:
                from adapters.splunk_adapter import SplunkAdapter

                wrote = SplunkAdapter().write_to_hec({
                    "incident_id": str(incident_id),
                    "action_taken": f"level_{level}",
                    "response_level": level,
                    "source_system": norm.source_system,
                    "severity": risk.severity_label,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                log.info("PIPELINE [8/8] Splunk HEC writeback success=%s", wrote)
            except Exception as he:
                log.warning("PIPELINE [8/8] HEC write-back failed: %s", he)
        else:
            log.info("PIPELINE [8/8] Splunk HEC writeback skipped")

        log.info("PIPELINE complete incident_id=%s mode=%s level=%s", incident_id, mode, level)
        return {
            "success": True,
            "incident_id": str(incident_id),
            "mode": mode,
            "response_level": level,
        }

    except Exception as e:
        try:
            await db.rollback()
        except Exception:
            pass
        log.error("PIPELINE failed at %s: %s\n%s", step_name, e, traceback.format_exc())
        return {"success": False, "error": str(e), "step": step_name}
