from datetime import datetime, timezone
from io import BytesIO
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import current_user, envelope
from api.incidents import api_incident_pdf
from db.session import get_db

router = APIRouter(prefix="/reports", tags=["reports"])
api_router = APIRouter(prefix="/api/reports", tags=["reports"])


async def _compute_summary(db: AsyncSession, period_days: int) -> dict:
    total = (await db.execute(text("""
        SELECT COUNT(*) FROM incidents WHERE first_seen >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).scalar() or 0

    by_sev_rows = (await db.execute(text("""
        SELECT severity, COUNT(*) AS n FROM incidents
        WHERE first_seen >= NOW() - (:days * INTERVAL '1 day')
        GROUP BY severity
    """), {"days": period_days})).mappings().all()
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in by_sev_rows:
        sv = int(r["severity"] or 2)
        if sv == 5: by_severity["critical"] = int(r["n"])
        elif sv == 4: by_severity["high"] = int(r["n"])
        elif sv == 3: by_severity["medium"] = int(r["n"])
        else: by_severity["low"] += int(r["n"])

    top_assets_rows = (await db.execute(text("""
        SELECT a.hostname, a.ip, COUNT(i.id) AS n
        FROM incidents i
        JOIN assets a ON a.id = i.primary_asset_id
        WHERE i.first_seen >= NOW() - (:days * INTERVAL '1 day')
        GROUP BY a.hostname, a.ip
        ORDER BY n DESC
        LIMIT 10
    """), {"days": period_days})).mappings().all()
    top_assets = [
        {"hostname": r["hostname"], "ip": r["ip"], "incident_count": int(r["n"])}
        for r in top_assets_rows
    ]

    avg_dwell = (await db.execute(text("""
        SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (last_seen - first_seen))/3600),0)
        FROM incidents WHERE first_seen >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).scalar() or 0
    mttd = (await db.execute(text("""
        SELECT AVG(EXTRACT(EPOCH FROM (triaged_at - first_seen))/3600)
        FROM incidents WHERE triaged_at IS NOT NULL
          AND first_seen >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).scalar()
    mttr = (await db.execute(text("""
        SELECT AVG(EXTRACT(EPOCH FROM (closed_at - first_seen))/3600)
        FROM incidents WHERE closed_at IS NOT NULL
          AND first_seen >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).scalar()

    containment = (await db.execute(text("""
        SELECT
          COUNT(*) FILTER (WHERE status = 'executed') AS ok,
          COUNT(*) AS total
        FROM response_actions
        WHERE incident_id IN (
          SELECT id FROM incidents
          WHERE created_at >= NOW() - (:days * INTERVAL '1 day')
        )
    """), {"days": period_days})).mappings().first()
    total_actions = int(containment["total"]) if containment else 0
    success_rate = (int(containment["ok"]) / total_actions * 100) if total_actions else 0.0

    fp_row = (await db.execute(text("""
        SELECT
          COUNT(*) FILTER (WHERE is_false_positive) AS fp,
          GREATEST(COUNT(*),1) AS total
        FROM incidents
        WHERE first_seen >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).mappings().first()
    fp_rate = (int(fp_row["fp"]) / int(fp_row["total"]) * 100) if fp_row["total"] else 0.0

    top_src_rows = (await db.execute(text("""
        SELECT src_ip AS ip, COUNT(*) AS n FROM alerts
        WHERE src_ip IS NOT NULL AND src_ip <> '0.0.0.0'
          AND event_time >= NOW() - (:days * INTERVAL '1 day')
        GROUP BY src_ip ORDER BY n DESC LIMIT 10
    """), {"days": period_days})).mappings().all()
    top_attack_sources = [{"ip": r["ip"], "count": int(r["n"])} for r in top_src_rows]

    cia = (await db.execute(text("""
        SELECT
          COALESCE(SUM(cia_c),0) AS c,
          COALESCE(SUM(cia_i),0) AS i,
          COALESCE(SUM(cia_a),0) AS a
        FROM incidents
        WHERE first_seen >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).mappings().first()

    auto_blocked = (await db.execute(text("""
        SELECT COUNT(DISTINCT target) FROM response_actions
        WHERE action_type = 'block_ip' AND status = 'executed' AND initiated_by = 'auto_pipeline'
          AND initiated_at >= NOW() - (:days * INTERVAL '1 day')
    """), {"days": period_days})).scalar() or 0

    return {
        "period_days": period_days,
        "total_incidents": int(total),
        "by_severity": by_severity,
        "top_assets": top_assets,
        "avg_dwell_hours": round(float(avg_dwell), 2),
        "mttd_hours": float(mttd) if mttd is not None else None,
        "mttr_hours": float(mttr) if mttr is not None else None,
        "containment_success_rate": round(float(success_rate), 2),
        "false_positive_rate": round(float(fp_rate), 2),
        "top_attack_sources": top_attack_sources,
        "cia_breakdown": {
            "c_total": int(cia["c"]),
            "i_total": int(cia["i"]),
            "a_total": int(cia["a"]),
        },
        "response_actions_total": total_actions,
        "auto_blocked_ips": int(auto_blocked),
    }


@router.get("/summary")
async def summary(
    period_days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    return envelope(await _compute_summary(db, period_days))


@router.get("/pdf")
async def pdf(
    period_days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    if user.get("role") in {"viewer", "degraded"}:
        raise HTTPException(status_code=403, detail="PDF export is not permitted for this role")
    data = await _compute_summary(db, period_days)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = _render_html(data, generated)

    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html).write_pdf()
    except Exception as e:
        return Response(
            content=f"PDF generation failed: {e}".encode(),
            status_code=500, media_type="text/plain",
        )

    filename = f"zerotrust-report-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/incidents/{incident_id}")
async def incident_report_pdf(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    return await api_incident_pdf(incident_id=incident_id, db=db, user=user)


@api_router.get("/incidents/{incident_id}")
async def api_incident_report_pdf(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    return await api_incident_pdf(incident_id=incident_id, db=db, user=user)


def _render_html(d: dict, generated: str) -> str:
    def _row(label, val):
        return f"<tr><td>{label}</td><td>{val}</td></tr>"
    assets_rows = "".join(
        f"<tr><td>{a['hostname']}</td><td>{a['ip']}</td><td>{a['incident_count']}</td></tr>"
        for a in d["top_assets"]
    ) or "<tr><td colspan='3'>No data</td></tr>"
    sources_rows = "".join(
        f"<tr><td>{s['ip']}</td><td>{s['count']}</td></tr>" for s in d["top_attack_sources"]
    ) or "<tr><td colspan='2'>No data</td></tr>"

    return f"""
<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<style>
  @page {{ size: A4; margin: 20mm; }}
  body {{ font-family: Helvetica, Arial, sans-serif; color:#0F172A; font-size: 11pt; }}
  h1 {{ color:#1E3A8A; margin-bottom: 0; }}
  .sub {{ color:#64748B; font-size: 10pt; margin-top: 4px; }}
  h2 {{ color:#1E3A8A; border-bottom: 1px solid #CBD5E1; padding-bottom: 4px; margin-top: 20px; }}
  table {{ width:100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ padding: 6px 8px; border-bottom: 1px solid #E2E8F0; text-align: left; font-size: 10pt; }}
  th {{ background:#F1F5F9; }}
  .kpi-grid {{ display:flex; gap:10px; margin-top:8px; }}
  .kpi {{ flex:1; background:#F8FAFC; border:1px solid #CBD5E1; padding:10px; border-radius:4px; }}
  .kpi .label {{ color:#64748B; font-size:9pt; text-transform:uppercase; }}
  .kpi .val   {{ font-size:16pt; font-weight:700; color:#1E3A8A; }}
</style>
</head>
<body>
  <h1>ZeroTrustX — SOC Report</h1>
  <div class='sub'>Generated {generated} · Period: last {d['period_days']} days</div>

  <h2>Summary</h2>
  <div class='kpi-grid'>
    <div class='kpi'><div class='label'>Total Incidents</div><div class='val'>{d['total_incidents']}</div></div>
    <div class='kpi'><div class='label'>MTTD (hrs)</div><div class='val'>{d['mttd_hours'] if d['mttd_hours'] is not None else '—'}</div></div>
    <div class='kpi'><div class='label'>MTTR (hrs)</div><div class='val'>{d['mttr_hours'] if d['mttr_hours'] is not None else '—'}</div></div>
    <div class='kpi'><div class='label'>FP Rate</div><div class='val'>{d['false_positive_rate']}%</div></div>
  </div>

  <h2>Severity Distribution</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {_row("Critical", d['by_severity']['critical'])}
    {_row("High", d['by_severity']['high'])}
    {_row("Medium", d['by_severity']['medium'])}
    {_row("Low", d['by_severity']['low'])}
  </table>

  <h2>Key Metrics</h2>
  <table>
    {_row("Avg dwell hours", d['avg_dwell_hours'])}
    {_row("Containment success rate", f"{d['containment_success_rate']}%")}
    {_row("Response actions total", d['response_actions_total'])}
    {_row("Auto-blocked IPs", d['auto_blocked_ips'])}
  </table>

  <h2>Top Targeted Assets</h2>
  <table>
    <tr><th>Hostname</th><th>IP</th><th>Incidents</th></tr>
    {assets_rows}
  </table>

  <h2>Top Attack Sources</h2>
  <table>
    <tr><th>IP</th><th>Alerts</th></tr>
    {sources_rows}
  </table>

  <h2>CIA Impact Totals</h2>
  <table>
    {_row("Confidentiality", d['cia_breakdown']['c_total'])}
    {_row("Integrity", d['cia_breakdown']['i_total'])}
    {_row("Availability", d['cia_breakdown']['a_total'])}
  </table>
</body>
</html>
"""
