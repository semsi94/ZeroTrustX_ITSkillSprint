import asyncio
import logging

from db.session import SessionLocal
from services.reputation_service import enrich_ip_now, enqueue_or_cache_ips
from workers.celery_app import celery_app

log = logging.getLogger("zerotrustx.reputation")


@celery_app.task(bind=True, max_retries=3, name="reputation.enrich_ip")
def enrich_ip_task(self, ip: str, incident_id: str | None = None):
    async def _run():
        async with SessionLocal() as db:
            return await enrich_ip_now(db, ip, incident_id=incident_id, force=True)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        log.exception("IP reputation enrichment failed for %s", ip)
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=min(300, 30 * (self.request.retries + 1)))
        return {"success": False, "ip": ip, "error": str(exc) or exc.__class__.__name__}


@celery_app.task(name="reputation.enrich_ip_batch")
def enrich_ip_batch_task(ips: list[str], incident_id: str | None = None):
    results = []
    for ip in ips or []:
        results.append(enrich_ip_task(ip, incident_id))
    return {"success": True, "count": len(results), "results": results}


@celery_app.task(name="reputation.refresh_expired_reputation")
def refresh_expired_reputation_task(limit: int = 100):
    async def _run():
        from sqlalchemy import text

        async with SessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT ip_address FROM ip_reputation
                WHERE expires_at IS NULL OR expires_at <= NOW()
                ORDER BY expires_at ASC NULLS FIRST
                LIMIT :limit
            """), {"limit": max(1, min(500, int(limit or 100)))})).scalars().all()
            return await enqueue_or_cache_ips(db, list(rows), source_system="scheduled_refresh", force=True)

    return asyncio.run(_run())


@celery_app.task(name="reputation.daily_seen_ip_refresh")
def daily_seen_ip_refresh_task():
    return refresh_expired_reputation_task(100)
