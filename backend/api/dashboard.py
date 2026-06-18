from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user, envelope
from config import get_settings
from db.session import get_db
from services.demo_mode import demo_catalog

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db), user: dict = Depends(current_user)):
    settings = get_settings()
    demo_status = demo_catalog()["meta"]["status_summary"] if settings.DEMO_MODE else {}
    total_incidents = (await db.execute(text("SELECT COUNT(*) FROM incidents"))).scalar() or 0
    assets_monitored = (await db.execute(text("SELECT COUNT(*) FROM assets WHERE COALESCE(is_placeholder, FALSE) = FALSE"))).scalar() or 0
    alerts_today = (await db.execute(text("""
        SELECT COUNT(*) FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
    """))).scalar() or 0
    response_actions_count = (await db.execute(text("""
        SELECT COUNT(*) FROM containment_actions
        WHERE requested_at >= NOW() - INTERVAL '30 days'
    """))).scalar() or 0
    evidence_events = (await db.execute(text("SELECT COUNT(*) FROM evidence"))).scalar() or 0

    open_rows = (await db.execute(text("""
        SELECT
          COUNT(*) FILTER (WHERE severity = 5) AS critical,
          COUNT(*) FILTER (WHERE severity = 4) AS high,
          COUNT(*) FILTER (WHERE severity = 3) AS medium,
          COUNT(*) FILTER (WHERE severity IN (1,2)) AS low,
          COUNT(*) AS total
        FROM incidents
        WHERE status NOT IN ('closed','false_positive')
    """))).mappings().first()

    zone_rows = (await db.execute(text("""
        SELECT COALESCE(a.zone,'unknown') AS zone, COUNT(*) AS n
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.primary_asset_id
        WHERE i.status NOT IN ('closed','false_positive')
        GROUP BY COALESCE(a.zone,'unknown')
    """))).mappings().all()
    by_zone = {}
    for r in zone_rows:
        z = (r["zone"] or "unknown").lower()
        by_zone[z] = int(r["n"])

    cia_rows = (await db.execute(text("""
        SELECT
          COALESCE(AVG(cia_c) * 50,0) AS c,
          COALESCE(AVG(cia_i) * 50,0) AS i,
          COALESCE(AVG(cia_a) * 50,0) AS a
        FROM incidents
        WHERE status NOT IN ('closed','false_positive')
    """))).mappings().first()
    cia_scores = {
        "c": round(float(cia_rows["c"]), 1),
        "i": round(float(cia_rows["i"]), 1),
        "a": round(float(cia_rows["a"]), 1),
    }
    if settings.DEMO_MODE:
        cia_scores = {
            "c": max(cia_scores["c"], 68.0),
            "i": max(cia_scores["i"], 56.0),
            "a": max(cia_scores["a"], 34.0),
        }

    top_src = (await db.execute(text("""
        SELECT
          a.src_ip AS ip,
          COUNT(*) AS count,
          MAX(a.event_time) AS last_seen,
          MAX(r.overall_score) AS overall_score,
          MAX(r.overall_verdict) AS overall_verdict,
          MAX(r.abuseipdb_score) AS abuseipdb_score,
          MAX(r.virustotal_malicious) AS virustotal_malicious,
          MAX(r.virustotal_suspicious) AS virustotal_suspicious
        FROM alerts a
        LEFT JOIN ip_reputation r ON r.ip_address = a.src_ip
        WHERE a.src_ip IS NOT NULL AND a.src_ip <> '0.0.0.0'
          AND a.src_ip !~ '^(10\\.|192\\.168\\.|127\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)'
          AND a.created_at >= NOW() - INTERVAL '30 days'
        GROUP BY a.src_ip
        ORDER BY COALESCE(MAX(r.overall_score), 0) DESC, COUNT(*) DESC
        LIMIT 8
    """))).mappings().all()
    top_src_list = [
        {"ip": r["ip"], "count": int(r["count"]),
         "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
         "overall_score": int(r["overall_score"] or 0),
         "overall_verdict": r["overall_verdict"] or "unknown",
         "abuseipdb_score": int(r["abuseipdb_score"] or 0),
         "virustotal_malicious": int(r["virustotal_malicious"] or 0),
         "virustotal_suspicious": int(r["virustotal_suspicious"] or 0)}
        for r in top_src
    ]

    containments = (await db.execute(text("""
        SELECT action_type, target, incident_id, initiated_at
        FROM response_actions
        WHERE status = 'executed' AND reverted_at IS NULL
        ORDER BY initiated_at DESC
        LIMIT 20
    """))).mappings().all()
    active_containments = [
        {"action_type": r["action_type"], "target": r["target"],
         "incident_id": str(r["incident_id"]) if r["incident_id"] else None,
         "initiated_at": r["initiated_at"].isoformat() if r["initiated_at"] else None}
        for r in containments
    ]

    mttd_r = (await db.execute(text("""
        SELECT AVG(EXTRACT(EPOCH FROM (triaged_at - first_seen))/3600) AS v
        FROM incidents WHERE triaged_at IS NOT NULL
    """))).scalar()
    mttr_r = (await db.execute(text("""
        SELECT AVG(EXTRACT(EPOCH FROM (closed_at - first_seen))/3600) AS v
        FROM incidents WHERE closed_at IS NOT NULL
    """))).scalar()

    fp_row = (await db.execute(text("""
        SELECT
          COUNT(*) FILTER (WHERE is_false_positive) AS fp,
          GREATEST(COUNT(*),1) AS total
        FROM incidents
    """))).mappings().first()
    fp_rate = round(float(fp_row["fp"]) / float(fp_row["total"]) * 100, 2) if fp_row["total"] else 0.0
    if settings.DEMO_MODE and fp_rate < 12:
        fp_rate = 16.8

    trend_24 = (await db.execute(text("""
        WITH hours AS (
          SELECT generate_series(
            date_trunc('hour', NOW() - INTERVAL '23 hours'),
            date_trunc('hour', NOW()),
            INTERVAL '1 hour'
          ) AS h
        )
        SELECT hours.h AS hour, COUNT(i.id) AS n
        FROM hours
        LEFT JOIN incidents i ON date_trunc('hour', i.first_seen) = hours.h
        GROUP BY hours.h
        ORDER BY hours.h
    """))).mappings().all()
    trend_24h = [{"hour": r["hour"].isoformat(), "count": int(r["n"])} for r in trend_24]

    trend_7 = (await db.execute(text("""
        WITH days AS (
          SELECT generate_series(
            date_trunc('day', NOW() - INTERVAL '6 days'),
            date_trunc('day', NOW()),
            INTERVAL '1 day'
          ) AS d
        )
        SELECT days.d AS date, COUNT(i.id) AS n
        FROM days
        LEFT JOIN incidents i ON date_trunc('day', i.first_seen) = days.d
        GROUP BY days.d
        ORDER BY days.d
    """))).mappings().all()
    trend_7d = [{"date": r["date"].date().isoformat(), "count": int(r["n"])} for r in trend_7]

    last_evt_minutes = (await db.execute(text("""
        SELECT EXTRACT(EPOCH FROM (NOW() - MAX(event_time))) / 60 FROM alerts
    """))).scalar()

    return envelope({
        "total_incidents": int(total_incidents or demo_status.get("total_incidents") or 0),
        "alerts_today": int(alerts_today or demo_status.get("alerts_today") or 0),
        "events_ingested": int(max(evidence_events or 0, demo_status.get("events_ingested") or 0)),
        "assets_monitored": int(assets_monitored or demo_status.get("assets_monitored") or 0),
        "response_actions_count": int(response_actions_count or demo_status.get("response_actions") or 0),
        "reports_generated": int(demo_status.get("reports_generated") or 0),
        "open_incidents": {
            "critical": int(open_rows["critical"]),
            "high": int(open_rows["high"]),
            "medium": int(open_rows["medium"]),
            "low": int(open_rows["low"]),
            "total": int(open_rows["total"]),
        },
        "incidents_by_zone": by_zone,
        "cia_scores": cia_scores,
        "top_src_ips": top_src_list,
        "active_containments": active_containments,
        "mttd_hours": float(mttd_r) if mttd_r is not None else None,
        "mttr_hours": float(mttr_r) if mttr_r is not None else None,
        "false_positive_rate": fp_rate,
        "trend_24h": trend_24h,
        "trend_7d": trend_7d,
        "last_event_minutes_ago": int(last_evt_minutes) if last_evt_minutes is not None else None,
    })
