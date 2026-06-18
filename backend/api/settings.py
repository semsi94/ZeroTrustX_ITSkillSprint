import json
import ipaddress
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from adapters.pfsense_adapter import PfSenseAdapter
from adapters.splunk_adapter import SplunkAdapter
from api.deps import current_user, envelope, require_recent_mfa
from config import (
    SENSITIVE_KEYS,
    get_integration_configured_status,
    get_sensitive_status,
    get_settings,
    write_env_value,
)
from core.splunk_cache import clear_cache
from db.session import get_db
from services.demo_mode import demo_banner_meta, demo_health_snapshot, demo_schema_field, is_demo_mode

router = APIRouter(prefix="/settings", tags=["settings"])
api_router = APIRouter(prefix="/api/integrations", tags=["integrations"])

REDIS_KEY = "integration_status"
REDIS_TTL_SECONDS = 60

REQUIRED_KEYS = {
    "splunk": [
        "SPLUNK_HOST",
        "SPLUNK_PORT",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
    ],
    "pfsense": [
        "PFSENSE_HOST",
        "PFSENSE_USERNAME",
        "PFSENSE_PASSWORD",
        "PFSENSE_BLOCK_ALIAS",
    ],
}

OPTIONAL_KEYS = {
    "splunk": [
        "SPLUNK_SCHEME",
        "SPLUNK_VERIFY_SSL",
        "SPLUNK_DEFAULT_INDEX",
        "SPLUNK_DEFAULT_LIMIT",
        "SPLUNK_HEC_TOKEN",
        "SPLUNK_HEC_URL",
    ],
    "pfsense": [
        "PFSENSE_VERIFY_SSL",
        "PFSENSE_CA_CERT_TEXT",
        "PFSENSE_CA_CERT_PATH",
        "PFSENSE_TIMEOUT",
    ],
}


async def _redis():
    s = get_settings()
    return aioredis.from_url(s.REDIS_URL, decode_responses=True)


async def _redis_get(key: str) -> Optional[str]:
    try:
        r = await _redis()
        try:
            return await r.get(key)
        finally:
            await r.close()
    except Exception:
        return None


async def _redis_setex(key: str, ttl: int, value: str) -> None:
    try:
        r = await _redis()
        try:
            await r.setex(key, ttl, value)
        finally:
            await r.close()
    except Exception:
        pass


async def _redis_delete(key: str) -> None:
    try:
        r = await _redis()
        try:
            await r.delete(key)
        finally:
            await r.close()
    except Exception:
        pass


def _parse_bool_setting(value, *, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise HTTPException(
        status_code=422,
        detail=f"{key} must be true or false. Put CA certificate text in PFSENSE_CA_CERT_TEXT.",
    )


def _validate_ca_cert_text(value: str) -> None:
    if not value:
        return
    if "BEGIN CERTIFICATE" not in value or "END CERTIFICATE" not in value:
        raise HTTPException(status_code=422, detail="Invalid CA certificate format.")


def _validate_integration_values(integration: str, values: dict) -> dict:
    cleaned = dict(values or {})
    if integration != "pfsense":
        return cleaned

    if "PFSENSE_VERIFY_SSL" in cleaned:
        cleaned["PFSENSE_VERIFY_SSL"] = "true" if _parse_bool_setting(cleaned.get("PFSENSE_VERIFY_SSL"), key="PFSENSE_VERIFY_SSL") else "false"

    cert_text = str(cleaned.get("PFSENSE_CA_CERT_TEXT") or "")
    _validate_ca_cert_text(cert_text)

    if cleaned.get("PFSENSE_VERIFY_SSL") == "true":
        current = get_settings()
        cert_path = str(cleaned.get("PFSENSE_CA_CERT_PATH") or "").strip()
        has_ca_material = bool(
            cert_text.strip()
            or cert_path
            or getattr(current, "PFSENSE_CA_CERT_TEXT", "")
            or getattr(current, "PFSENSE_CA_CERT_PATH", "")
        )
        if not has_ca_material:
            raise HTTPException(
                status_code=422,
                detail="Verify SSL requires CA certificate text or CA certificate path.",
            )

    if "PFSENSE_TIMEOUT" in cleaned and cleaned.get("PFSENSE_TIMEOUT") not in (None, ""):
        try:
            timeout = int(cleaned["PFSENSE_TIMEOUT"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="PFSENSE_TIMEOUT must be a number of seconds.")
        if timeout < 1 or timeout > 120:
            raise HTTPException(status_code=422, detail="PFSENSE_TIMEOUT must be between 1 and 120 seconds.")
        cleaned["PFSENSE_TIMEOUT"] = str(timeout)

    return cleaned


def _test_service(service: str, overrides: Optional[dict] = None) -> dict:
    overrides = overrides or {}
    if service == "splunk":
        port_raw = overrides.get("SPLUNK_PORT")
        try:
            port = int(port_raw) if port_raw not in (None, "") else None
        except (TypeError, ValueError):
            port = None
        verify_raw = overrides.get("SPLUNK_VERIFY_SSL")
        if isinstance(verify_raw, str):
            verify_ssl = verify_raw.strip().lower() in {"1", "true", "yes", "on"}
        else:
            verify_ssl = verify_raw if verify_raw is not None else None
        return SplunkAdapter(
            host=overrides.get("SPLUNK_HOST") or None,
            port=port,
            scheme=overrides.get("SPLUNK_SCHEME") or None,
            username=overrides.get("SPLUNK_USERNAME") or None,
            password=overrides.get("SPLUNK_PASSWORD") or None,
            hec_token=overrides.get("SPLUNK_HEC_TOKEN") or None,
            hec_url=overrides.get("SPLUNK_HEC_URL") or None,
            index=overrides.get("SPLUNK_DEFAULT_INDEX") or None,
            verify_ssl=verify_ssl,
        ).test_connection()
    if service == "pfsense":
        verify_raw = overrides.get("PFSENSE_VERIFY_SSL")
        verify_ssl = _parse_bool_setting(verify_raw, key="PFSENSE_VERIFY_SSL") if verify_raw is not None else None
        return PfSenseAdapter(
            host=overrides.get("PFSENSE_HOST") or None,
            username=overrides.get("PFSENSE_USERNAME") or None,
            password=overrides.get("PFSENSE_PASSWORD") or None,
            block_alias=overrides.get("PFSENSE_BLOCK_ALIAS") or None,
            verify_ssl=verify_ssl,
            ca_cert_text=overrides.get("PFSENSE_CA_CERT_TEXT") or None,
            ca_cert_path=overrides.get("PFSENSE_CA_CERT_PATH") or None,
            timeout=overrides.get("PFSENSE_TIMEOUT") or None,
        ).test_connection()
    return {"connected": False, "error": "Unknown service"}


async def _compute_status() -> dict:
    configured = get_integration_configured_status()
    settings = get_settings()
    now_iso = datetime.now(timezone.utc).isoformat()
    splunk_hec_configured = bool(settings.SPLUNK_HEC_TOKEN and settings.SPLUNK_HEC_URL)
    demo_mode = is_demo_mode()

    splunk_res = (
        _test_service("splunk")
        if configured["splunk"]
        else {"connected": False, "error": None}
    )
    pfsense_res = (
        _test_service("pfsense")
        if configured["pfsense"]
        else {"connected": False, "error": None}
    )
    reputation_configured = configured.get("reputation", False)
    if demo_mode:
        splunk_hec_configured = True
        reputation_configured = True

    return {
        **(demo_banner_meta() if demo_mode else {}),
        "splunk": {
            "configured": configured["splunk"],
            "management_configured": configured["splunk"],
            "hec_configured": splunk_hec_configured,
            "connected": bool(splunk_res.get("connected")),
            "search_api": "connected" if bool(splunk_res.get("search_connected") or splunk_res.get("connected")) else ("error" if configured["splunk"] else "not_configured"),
            "hec": "connected" if splunk_res.get("hec_connected") else ("error" if splunk_hec_configured else "not_configured"),
            "saved_searches": "connected" if splunk_res.get("saved_searches_accessible") else ("error" if configured["splunk"] else "not_configured"),
            "alerts_reports": "connected" if splunk_res.get("alerts_accessible") else ("error" if configured["splunk"] else "not_configured"),
            "search_connected": bool(splunk_res.get("search_connected") or splunk_res.get("connected")),
            "management_connected": bool(splunk_res.get("rest_connected") or splunk_res.get("connected")),
            "fully_connected": bool((splunk_res.get("search_connected") or splunk_res.get("connected")) and splunk_hec_configured and splunk_res.get("hec_connected")),
            "error": splunk_res.get("error"),
            "version": splunk_res.get("version"),
            "rest_connected": splunk_res.get("rest_connected"),
            "hec_connected": splunk_res.get("hec_connected"),
            "hec_error": splunk_res.get("hec_error"),
            "saved_searches_accessible": splunk_res.get("saved_searches_accessible"),
            "saved_searches_error": splunk_res.get("saved_searches_error"),
            "alerts_accessible": splunk_res.get("alerts_accessible"),
            "alerts_error": splunk_res.get("alerts_error"),
            "search_query": splunk_res.get("search_query"),
            "tested_at": now_iso if configured["splunk"] else None,
            "last_tested": now_iso if configured["splunk"] else None,
            "mode": "simulated" if demo_mode else "live",
        },
        "pfsense": {
            "configured": configured["pfsense"],
            "connected": bool(pfsense_res.get("connected")),
            "status": pfsense_res.get("status"),
            "message": pfsense_res.get("message"),
            "error": pfsense_res.get("error"),
            "version": pfsense_res.get("version"),
            "verify_ssl": bool(settings.PFSENSE_VERIFY_SSL),
            "ca_cert_configured": bool(settings.PFSENSE_CA_CERT_TEXT or settings.PFSENSE_CA_CERT_PATH),
            "ca_cert_source": "text" if settings.PFSENSE_CA_CERT_TEXT else ("path" if settings.PFSENSE_CA_CERT_PATH else None),
            "tested_at": now_iso if configured["pfsense"] else None,
            "last_tested": now_iso if configured["pfsense"] else None,
            "mode": "simulated" if demo_mode else "live",
        },
        "reputation": {
            "configured": reputation_configured,
            "enabled": bool(settings.IP_REPUTATION_ENABLED),
            "abuseipdb_configured": True if demo_mode else bool(settings.ABUSEIPDB_API_KEY),
            "virustotal_configured": True if demo_mode else bool(settings.VIRUSTOTAL_API_KEY),
            "full_reputation_available": True if demo_mode else bool(settings.ABUSEIPDB_API_KEY and settings.VIRUSTOTAL_API_KEY),
            "status": "connected" if reputation_configured else "not_configured",
            "warning": None if reputation_configured else "Full IP reputation requires both AbuseIPDB and VirusTotal.",
            "last_tested": now_iso if demo_mode else None,
            "mode": "simulated" if demo_mode else "live",
        },
    }


def _degraded_status() -> dict:
    return {
        "splunk": {
            "configured": False,
            "management_configured": False,
            "hec_configured": False,
            "connected": False,
            "search_connected": False,
            "management_connected": False,
            "fully_connected": False,
            "saved_searches_accessible": False,
            "alerts_accessible": False,
            "error": "Status check failed",
        },
        "pfsense": {"configured": False, "connected": False, "error": "Status check failed"},
        "reputation": {"configured": False, "enabled": False, "error": "Status check failed"},
    }


@router.get("/integration-status")
async def integration_status(refresh: bool = False):
    try:
        if refresh:
            await _redis_delete(REDIS_KEY)
        else:
            cached = await _redis_get(REDIS_KEY)
            if cached:
                return json.loads(cached)

        data = await _compute_status()
        await _redis_setex(REDIS_KEY, REDIS_TTL_SECONDS, json.dumps(data))
        return data
    except Exception:
        return _degraded_status()


class IntegrationIn(BaseModel):
    integration: str
    values: dict


@router.post("/integrations")
async def update_integration(
    body: IntegrationIn,
    user: dict = Depends(require_recent_mfa),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    if body.integration not in REQUIRED_KEYS:
        raise HTTPException(status_code=400, detail="Unknown integration")
    if not body.values:
        raise HTTPException(status_code=400, detail="No values provided")

    allowed = set(REQUIRED_KEYS[body.integration] + OPTIONAL_KEYS[body.integration])
    provided = set(body.values.keys())
    invalid = sorted(provided - allowed)
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid keys: {invalid}")

    values = _validate_integration_values(body.integration, body.values)

    for key, value in values.items():
        write_env_value(key, "" if value is None else str(value))

    await _redis_delete(REDIS_KEY)
    status = await _compute_status()
    cache_info = {"cacheCleared": False, "deletedCachedEvents": 0}
    if body.integration == "splunk":
        touched_required = bool(set(body.values.keys()) & set(REQUIRED_KEYS["splunk"]))
        critical_missing = any(not str(body.values.get(k, "keep")).strip() for k in REQUIRED_KEYS["splunk"] if k in body.values)
        search_failed = not bool(status["splunk"].get("search_connected") or status["splunk"].get("connected"))
        if touched_required and (critical_missing or search_failed):
            try:
                cache_info["deletedCachedEvents"] = await clear_cache()
                cache_info["cacheCleared"] = True
            except Exception:
                cache_info["cacheClearError"] = "Cache clear failed"
    return envelope({body.integration: status[body.integration], **cache_info})


@api_router.post("/splunk/disconnect")
async def disconnect_splunk(user: dict = Depends(require_recent_mfa)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    for key in [
        "SPLUNK_HOST",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
        "SPLUNK_HEC_TOKEN",
        "SPLUNK_HEC_URL",
    ]:
        write_env_value(key, "")
    await _redis_delete(REDIS_KEY)
    deleted = await clear_cache()
    return {
        "success": True,
        "cacheCleared": True,
        "deletedCachedEvents": deleted,
        "error": None,
    }


class TestConnectionIn(BaseModel):
    integration: str
    values: Optional[dict] = None


class BlockIpIn(BaseModel):
    ip: str
    alias: Optional[str] = None


@router.post("/test-connection")
async def test_connection(
    body: TestConnectionIn,
    user: dict = Depends(require_recent_mfa),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    if body.integration not in REQUIRED_KEYS:
        raise HTTPException(status_code=400, detail="Unknown integration")

    overrides = None
    if body.values:
        allowed = set(REQUIRED_KEYS[body.integration] + OPTIONAL_KEYS[body.integration])
        invalid = sorted(set(body.values.keys()) - allowed)
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid keys: {invalid}")
        overrides = _validate_integration_values(body.integration, body.values)

    if not overrides and not get_integration_configured_status().get(body.integration):
        return envelope({
            "integration": body.integration,
            "connected": False,
            "error": "Not configured",
            "tested_at": datetime.now(timezone.utc).isoformat(),
        })

    res = _test_service(body.integration, overrides)
    await _redis_delete(REDIS_KEY)
    return envelope({
        "integration": body.integration,
        "connected": bool(res.get("connected")),
        "success": bool(res.get("success", res.get("connected"))),
        "status": res.get("status") or ("connected" if res.get("connected") else "error"),
        "message": res.get("message"),
        "error": res.get("error"),
        "version": res.get("version"),
        "rest_connected": res.get("rest_connected"),
        "management_connected": bool(res.get("rest_connected") or res.get("connected")) if body.integration == "splunk" else None,
        "search_connected": bool(res.get("search_connected") or res.get("connected")) if body.integration == "splunk" else None,
        "hec_connected": res.get("hec_connected"),
        "hec_error": res.get("hec_error"),
        "saved_searches_accessible": res.get("saved_searches_accessible"),
        "saved_searches_error": res.get("saved_searches_error"),
        "alerts_accessible": res.get("alerts_accessible"),
        "alerts_error": res.get("alerts_error"),
        "search_query": res.get("search_query"),
        "ad_hoc": overrides is not None,
        "tested_at": datetime.now(timezone.utc).isoformat(),
    })


@api_router.get("/pfsense/test")
async def pfsense_test(user: dict = Depends(current_user)):
    res = PfSenseAdapter().test_connection()
    return {
        "success": bool(res.get("success", res.get("connected"))),
        "status": res.get("status") or ("connected" if res.get("connected") else "error"),
        "message": res.get("message") or ("pfSense connection successful" if res.get("connected") else "pfSense connection failed"),
        "error": res.get("error"),
    }


@api_router.post("/pfsense/block-ip")
async def pfsense_block_ip(body: BlockIpIn, user: dict = Depends(current_user)):
    if user["role"] not in ("admin", "senior_analyst"):
        raise HTTPException(status_code=403, detail="Senior role required")
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    try:
        result = PfSenseAdapter().add_to_alias(body.ip, body.alias)
        return {
            "success": True,
            "action": "block_ip",
            "ip": body.ip,
            "alias": result.get("alias") or body.alias,
            "error": None,
        }
    except Exception as e:
        return {
            "success": False,
            "action": "block_ip",
            "ip": body.ip,
            "alias": body.alias,
            "error": str(e) or e.__class__.__name__,
        }


@router.get("/system-info")
async def system_info(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(current_user),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    s = get_settings()
    demo_mode = is_demo_mode()

    try:
        db_ok = bool((await db.execute(text("SELECT 1"))).scalar())
    except Exception:
        db_ok = False

    redis_ok = False
    try:
        r = await _redis()
        try:
            redis_ok = bool(await r.ping())
        finally:
            await r.close()
    except Exception:
        redis_ok = False

    async def count_table(table_name: str) -> int:
        try:
            return int((await db.execute(text(f"SELECT COUNT(*) FROM {table_name}"))).scalar() or 0)
        except Exception:
            return 0

    mitre_synced = await count_table("mitre_techniques") > 0

    return envelope({
        "app_version": s.APP_VERSION,
        "db_connected": db_ok,
        "redis_connected": redis_ok,
        "celery_connected": True if demo_mode else redis_ok,
        "mitre_synced": True if demo_mode else mitre_synced,
        "total_incidents": await count_table("incidents"),
        "total_alerts": await count_table("alerts"),
        "total_assets": await count_table("assets"),
        "webhook_url": "/webhooks/splunk",
        "last_hec_write": None,
        **(demo_health_snapshot() if demo_mode else {}),
    })


@router.get("/integrations/schema")
async def schema(user: dict = Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    s = get_settings()
    demo_mode = is_demo_mode()
    enc_status = get_sensitive_status()

    def field_info(key: str):
        val = getattr(s, key, "") or ""
        if demo_mode and not val:
            return demo_schema_field(key, val, key in SENSITIVE_KEYS)
        if key in SENSITIVE_KEYS:
            return {
                "value": "",
                "is_set": bool(val),
                "encrypted": bool(enc_status.get(key, False)),
                "sensitive": True,
            }
        return {
            "value": str(val),
            "is_set": bool(val),
            "encrypted": False,
            "sensitive": False,
        }

    return envelope({
        "splunk": {
            "required": REQUIRED_KEYS["splunk"],
            "optional": OPTIONAL_KEYS["splunk"],
            "fields": {
                k: field_info(k)
                for k in (REQUIRED_KEYS["splunk"] + OPTIONAL_KEYS["splunk"])
            },
        },
        "pfsense": {
            "required": REQUIRED_KEYS["pfsense"],
            "optional": OPTIONAL_KEYS["pfsense"],
            "fields": {
                k: field_info(k)
                for k in (REQUIRED_KEYS["pfsense"] + OPTIONAL_KEYS["pfsense"])
            },
        },
        "reputation": {
            "required": ["ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY"],
            "optional": ["IP_REPUTATION_ENABLED", "IP_REPUTATION_AUTO_INCIDENT_ENABLED", "IP_REPUTATION_MAX_REQUESTS_PER_MINUTE", "IP_REPUTATION_DEFAULT_CACHE_HOURS"],
            "fields": {
                k: field_info(k)
                for k in [
                    "ABUSEIPDB_API_KEY",
                    "VIRUSTOTAL_API_KEY",
                    "IP_REPUTATION_ENABLED",
                    "IP_REPUTATION_AUTO_INCIDENT_ENABLED",
                    "IP_REPUTATION_MAX_REQUESTS_PER_MINUTE",
                    "IP_REPUTATION_DEFAULT_CACHE_HOURS",
                ]
            },
        },
    })
