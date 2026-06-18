import hashlib
import json
from typing import Any


def _dig(data: Any, path: str):
    cur = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(data: dict, keys: list[str]) -> str:
    for key in keys:
        value = data.get(key)
        if value in (None, ""):
            value = _dig(data, key)
        if value not in (None, ""):
            return str(value)
    return ""


def _raw_dict(raw: Any) -> dict:
    if isinstance(raw, dict) and "result" in raw and isinstance(raw["result"], dict):
        raw = raw["result"]
    if not isinstance(raw, dict):
        return {"_raw": raw}

    merged = dict(raw)
    raw_text = raw.get("_raw")
    if isinstance(raw_text, str):
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                merged = {**parsed, **merged}
        except Exception:
            pass
    return merged


def _severity(value: str) -> str:
    text = str(value or "").lower()
    if text in {"5", "critical", "crit", "error", "err", "fatal", "high"}:
        return "high"
    if text in {"4", "3", "warn", "warning", "medium", "med"}:
        return "medium"
    if text in {"2", "1", "info", "informational", "low", "notice", "debug"}:
        return "low"
    return "unknown"


def _readable_action(action: str) -> str:
    text = str(action or "")
    up = text.upper()
    if up in {"LOGIN_FAILURE", "LOGIN_FAILED", "AUTH_FAILURE", "AUTH_FAILED"}:
        return "Failed login"
    if up in {"LOGIN_SUCCESS", "AUTH_SUCCESS"}:
        return "Successful login"
    return text


def _readable_category(category: str) -> str:
    text = str(category or "")
    return "Authentication" if text.upper() == "AUTH" else text


def normalize_splunk_event(raw_result: Any) -> dict:
    raw = _raw_dict(raw_result)
    level = _first(raw, ["level", "severity", "log_level", "alert.severity"])
    action = _readable_action(_first(raw, ["action", "event.action"]))
    category = _readable_category(_first(raw, ["event_category", "category", "event.category"]))
    message = _first(raw, ["message", "msg", "signature", "rule_name", "alert.signature", "_raw"])
    error_status = _first(raw, ["details.error.status", "error.status"])
    status_code = _first(raw, ["status_code", "status", "http_status", "details.error.status"])
    email = _first(raw, ["email", "details.email", "details.payload.email", "user.email"])
    user = _first(raw, ["user", "username", "email", "details.email", "details.payload.email", "user.name"])
    time_value = _first(raw, ["timestamp", "_time", "time", "event_time"])
    identity = "|".join([
        time_value,
        _first(raw, ["index"]),
        _first(raw, ["sourcetype"]),
        _first(raw, ["host", "hostname"]),
        message,
        str(raw.get("_cd") or raw.get("_bkt") or ""),
    ])

    return {
        "id": str(raw.get("_cd") or raw.get("event_id") or hashlib.sha1(identity.encode()).hexdigest()[:16]),
        "time": time_value,
        "_time": time_value,
        "level": level,
        "severity": _severity(level or category or status_code),
        "index": _first(raw, ["index"]),
        "sourcetype": _first(raw, ["sourcetype"]),
        "host": _first(raw, ["host", "hostname", "computer_name", "dest_host"]),
        "source": _first(raw, ["source"]),
        "source_ip": _first(raw, ["source_ip", "src_ip", "src", "clientip", "client_ip"]),
        "destination_ip": _first(raw, ["destination_ip", "dest_ip", "dest", "dst"]),
        "destination_port": _first(raw, ["destination_port", "dest_port", "dpt", "port"]),
        "user": user,
        "email": email,
        "action": action,
        "category": category,
        "outcome": _first(raw, ["outcome", "result", "statusText", "details.error.statusText"]),
        "message": message,
        "method": _first(raw, ["method", "http_method", "request_method"]),
        "path": _first(raw, ["path", "uri", "url", "details.route"]),
        "original_url": _first(raw, ["original_url", "url", "uri"]),
        "status_code": status_code,
        "authenticated": _first(raw, ["authenticated", "auth", "is_authenticated"]),
        "user_agent": _first(raw, ["user_agent", "http_user_agent", "userAgent"]),
        "referrer": _first(raw, ["referrer", "referer", "http_referrer"]),
        "error_status": error_status,
        "error_status_text": _first(raw, ["details.error.statusText", "error.statusText"]),
        "error_message": _first(raw, ["details.error.message", "error.message"]),
        "raw": raw,
    }
