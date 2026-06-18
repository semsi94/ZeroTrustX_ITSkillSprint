import logging
import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, text
import redis.asyncio as aioredis

from api import (
    account as account_router,
    alerts_ingest as alerts_ingest_router,
    alerts as alerts_router,
    assets as assets_router,
    auth as auth_router,
    dashboard as dashboard_router,
    demo as demo_router,
    evidence as evidence_router,
    firewall as firewall_router,
    incidents as incidents_router,
    investigation as investigation_router,
    mitre as mitre_router,
    reputation as reputation_router,
    reports as reports_router,
    response as response_router,
    settings as settings_router,
    splunk as splunk_router,
    tickets as tickets_router,
    webhooks as webhooks_router,
)
from api.deps import hash_password
from services.demo_seed_service import seed_demo_data
from db.base import Base
from db.session import SessionLocal, engine
from config import get_settings
import models  # noqa: F401 register models

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
log = logging.getLogger("zerotrustx")
LOCAL_SEED_USERS = [
    ("admin", "mammadov4103@gmail.com", "Admin", "admin", "SEED_ADMIN_PASSWORD"),
    ("analyst", "analyst@example.local", "SOC Analyst", "soc_analyst", "SEED_ANALYST_PASSWORD"),
    ("viewer", "viewer@example.local", "Viewer", "viewer", "SEED_VIEWER_PASSWORD"),
]

app = FastAPI(title="ZeroTrustX", version="1.0.0")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(status_code=400, content={"success": False, "error": "Invalid request payload", "detail": exc.errors()})


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "error": exc.detail.get("message", "Request failed"), **exc.detail},
        )
    return JSONResponse(status_code=exc.status_code, content={"success": False, "error": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    log.exception("Unhandled request error")
    return JSONResponse(status_code=500, content={"success": False, "error": "Internal server error"})

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"^http://(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+):(3000|5173)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(auth_router.api_router)
app.include_router(account_router.router)
app.include_router(webhooks_router.router)
app.include_router(dashboard_router.router)
app.include_router(demo_router.router)
app.include_router(incidents_router.router)
app.include_router(incidents_router.api_router)
app.include_router(alerts_router.router)
app.include_router(alerts_ingest_router.router)
app.include_router(assets_router.router)
app.include_router(response_router.router)
app.include_router(firewall_router.router)
app.include_router(reports_router.router)
app.include_router(reports_router.api_router)
app.include_router(settings_router.router)
app.include_router(settings_router.api_router)
app.include_router(splunk_router.router)
app.include_router(tickets_router.router)
app.include_router(tickets_router.incident_router)
app.include_router(evidence_router.router)
app.include_router(investigation_router.router)
app.include_router(investigation_router.api_router)
app.include_router(mitre_router.router)
app.include_router(mitre_router.api_router)
app.include_router(mitre_router.incident_router)
app.include_router(mitre_router.api_incident_router)
app.include_router(reputation_router.router)
app.include_router(reputation_router.incident_router)

SCHEMA_TABLES = {
    "users",
    "assets",
    "incidents",
    "alerts",
    "response_actions",
    "evidence",
    "splunk_cached_events",
    "containment_actions",
    "investigation_search_cache",
    "login_attempts",
    "trusted_devices",
    "mfa_challenges",
    "user_preferences",
    "tickets",
    "incident_comments",
    "incident_activity",
    "external_alerts",
    "observables",
    "incident_mitre_links",
    "event_outbox",
    "idempotency_keys",
    "audit_log",
    "playbooks",
    "playbook_runs",
    "connector_credentials",
    "approval_requests",
    "mitre_tactics",
    "mitre_techniques",
    "mitre_technique_tactics",
    "mitre_sync_state",
    "evidence_mitre_links",
    "ip_reputation",
    "ip_observations",
    "incident_ip_reputation_links",
}

UPLOAD_ROOT = Path(__file__).parent / "uploads"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_ROOT)), name="uploads")


@app.get("/health")
async def health():
    db_status = "error"
    redis_status = "error"
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        log.exception("Health DB check failed")

    try:
        r = aioredis.from_url(get_settings().REDIS_URL, decode_responses=True)
        try:
            if await r.ping():
                redis_status = "ok"
        finally:
            await r.close()
    except Exception:
        log.exception("Health Redis check failed")

    return {"status": "ok", "db": db_status, "redis": redis_status}


def _alembic_config():
    from alembic.config import Config

    cfg = Config(str(Path(__file__).parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", get_settings().DATABASE_URL_SYNC)
    return cfg


def _ensure_existing_schema(sync_engine) -> None:
    Base.metadata.create_all(sync_engine)
    with sync_engine.begin() as conn:
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_last_seen ON incidents (last_seen)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_event_time ON alerts (event_time)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_response_actions_status ON response_actions (status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_splunk_cache_time ON splunk_cached_events (splunk_time)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_containment_actions_target ON containment_actions (target_ip)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigation_cache_expires ON investigation_search_cache (expires_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_login_attempts_created ON login_attempts (created_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_login_attempts_resolved_client_ip ON login_attempts (resolved_client_ip)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_trusted_devices_expires ON trusted_devices (expires_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_mfa_challenges_expires ON mfa_challenges (expires_at)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users (lower(email)) WHERE email IS NOT NULL"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_tickets_status ON tickets (status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_tickets_incident_id ON tickets (incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incident_comments_incident_id ON incident_comments (incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incident_activity_incident_id ON incident_activity (incident_id)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_external_alerts_dedupe_key ON external_alerts (dedupe_key)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_observables_incident_id ON observables (incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incident_mitre_links_incident_id ON incident_mitre_links (incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_event_outbox_status ON event_outbox (status)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_idempotency_keys_scope_key ON idempotency_keys (scope, key)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_mitre_tactics_tactic_id ON mitre_tactics (tactic_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_mitre_techniques_tactic_id ON mitre_techniques (tactic_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_mitre_technique_tactics_tactic_id ON mitre_technique_tactics (tactic_id)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_ip_reputation_ip_address ON ip_reputation (ip_address)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ip_observations_incident_id ON ip_observations (incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incident_ip_reputation_links_incident_id ON incident_ip_reputation_links (incident_id)"))


def _run_alembic_startup() -> None:
    from alembic import command

    settings = get_settings()
    cfg = _alembic_config()
    sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True, future=True)
    try:
        with sync_engine.begin() as conn:
            conn.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto"'))
            tables = set(conn.execute(text("""
                SELECT tablename FROM pg_tables WHERE schemaname = 'public'
            """)).scalars().all())

        has_version = "alembic_version" in tables
        has_schema_tables = bool(tables & SCHEMA_TABLES)

        if has_schema_tables and not has_version:
            command.stamp(cfg, "0001_initial")
            command.upgrade(cfg, "head")
            log.info("Stamped existing schema at initial revision, then applied remaining migrations")
            return

        command.upgrade(cfg, "head")
        log.info("Alembic migrations applied")
    finally:
        sync_engine.dispose()


@app.on_event("startup")
async def on_startup() -> None:
    db_ready = False
    for attempt in range(1, 11):
        try:
            await asyncio.to_thread(_run_alembic_startup)
            db_ready = True
            break
        except Exception:
            log.exception("Alembic startup attempt %s failed", attempt)
            if attempt == 10:
                try:
                    async with engine.begin() as conn:
                        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto"'))
                        await conn.run_sync(Base.metadata.create_all)
                        log.info("Verified tables with SQLAlchemy metadata fallback")
                        db_ready = True
                except Exception:
                    log.exception("Database unavailable at startup; continuing in degraded mode")
                break
            await asyncio.sleep(2)

    if db_ready:
        try:
            async with SessionLocal() as db:
                settings = get_settings()
                for username, email, display_name, role, password_key in LOCAL_SEED_USERS:
                    password = getattr(settings, password_key, "") or ""
                    if settings.DEMO_MODE and not password:
                        from services.demo_mode import demo_password_for_setting

                        password = demo_password_for_setting(password_key) or ""
                    password_hash = hash_password(password) if password else None
                    existing = (await db.execute(
                        text("SELECT id, password_hash FROM users WHERE lower(username) = lower(:username) OR lower(email) = lower(:email) LIMIT 1"),
                        {"username": username, "email": email},
                    )).scalar()
                    if existing:
                        set_password = ", password_hash = :password_hash" if password_hash else ""
                        await db.execute(text(f"""
                            UPDATE users
                            SET username = :username,
                                email = :email,
                                display_name = :display_name,
                                role = :role,
                                is_active = CASE WHEN :has_password THEN TRUE ELSE is_active END,
                                disabled = CASE WHEN :has_password THEN FALSE ELSE disabled END,
                                failed_login_count = 0,
                                locked_until = NULL,
                                updated_at = NOW()
                                {set_password}
                            WHERE id = :id
                        """), {
                            "id": str(existing),
                            "username": username,
                            "email": email,
                            "display_name": display_name,
                            "role": role,
                            "has_password": bool(password_hash),
                            "password_hash": password_hash,
                        })
                    else:
                        await db.execute(text("""
                            INSERT INTO users (username, email, display_name, password_hash, role, is_active, disabled)
                            VALUES (:username, :email, :display_name, :password_hash, :role, :is_active, :disabled)
                        """), {
                            "username": username,
                            "email": email,
                            "display_name": display_name,
                            "password_hash": password_hash or "disabled-local-account",
                            "role": role,
                            "is_active": bool(password_hash),
                            "disabled": not bool(password_hash),
                        })
                await db.commit()
                log.info("Verified local seed profiles for %s roles", len(LOCAL_SEED_USERS))
                if settings.DEMO_MODE and settings.DEMO_SEED_ON_START:
                    seeded = await seed_demo_data(db, reset_first=bool(settings.DEMO_RESET_ON_START))
                    log.info(
                        "Demo mode seed completed: incidents=%s events=%s",
                        seeded.get("incidents"),
                        seeded.get("events"),
                    )
        except Exception:
            log.exception("Admin seed skipped because the database is unavailable")
