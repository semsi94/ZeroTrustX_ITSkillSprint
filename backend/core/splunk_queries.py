import re
from typing import Optional

from adapters.splunk_adapter import SplunkAdapter, ensure_search_prefix


TIME_RANGES = {
    "Last 15m": "-15m",
    "Last 15 minutes": "-15m",
    "Last 1h": "-1h",
    "Last 1 hour": "-1h",
    "Last 4h": "-4h",
    "Last 4 hours": "-4h",
    "Last 24h": "-24h",
    "Last 24 hours": "-24h",
    "Last 7d": "-7d",
    "Last 7 days": "-7d",
    "Last 30d": "-30d",
    "Last 30 days": "-30d",
    "Last 90d": "-90d",
    "Last 90 days": "-90d",
    "All time": "0",
}

TIME_VALUE_RE = re.compile(r"^[A-Za-z0-9_:+./-]+$")


def safe_time(value: Optional[str], fallback: str) -> str:
    value = (value or fallback).strip()
    if value.lower() in {"all", "alltime"}:
        return "0"
    return value if TIME_VALUE_RE.match(value) else fallback


def escape_spl_value(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def resolve_time(time_range: Optional[str], earliest: Optional[str], latest: Optional[str]) -> tuple[str, str]:
    if time_range in TIME_RANGES:
        earliest = TIME_RANGES[time_range]
    return safe_time(earliest, "-24h"), safe_time(latest, "now")


def index_clause(adapter: SplunkAdapter, index: Optional[str] = None, force_index_all: bool = False) -> str:
    if force_index_all:
        return "index=*"
    configured = (index or adapter.default_index or "*").strip()
    if configured in {"", "all", "*"}:
        return "index=*"
    if configured.startswith("index=") or " OR " in configured:
        return configured
    indexes = [x.strip() for x in re.split(r"[, ]+", configured) if x.strip()]
    if not indexes:
        return "index=*"
    if len(indexes) == 1:
        return f"index={escape_spl_value(indexes[0])}"
    return "(" + " OR ".join(f"index={escape_spl_value(item)}" for item in indexes) + ")"


def field_filter(fields: list[str], value: Optional[str], wildcard: bool = False) -> Optional[str]:
    value = (value or "").strip()
    if not value:
        return None
    escaped = escape_spl_value(value)
    if wildcard:
        escaped = f"*{escaped}*"
    return "(" + " OR ".join(f'{field}="{escaped}"' for field in fields) + ")"


def append_head(spl: str, limit: int) -> str:
    if re.search(r"\|\s*head\s+\d+", spl, flags=re.I):
        return spl
    return f"{spl} | head {limit}"


def build_search(
    adapter: SplunkAdapter,
    *,
    spl: Optional[str] = None,
    index: Optional[str] = None,
    time_range: Optional[str] = None,
    earliest: Optional[str] = None,
    latest: Optional[str] = None,
    limit: int = 100,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    sourcetype: Optional[str] = None,
    source: Optional[str] = None,
    action: Optional[str] = None,
    status_code: Optional[str] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    user_agent: Optional[str] = None,
    authenticated: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
    exclude_keyword: Optional[str] = None,
    force_index_all: bool = False,
) -> str:
    limit = max(1, min(int(limit or 100), 1000))
    if spl and spl.strip():
        query = ensure_search_prefix(spl.strip())
        earliest_value, latest_value = resolve_time(time_range, earliest, latest)
        base, sep, rest = query.partition("|")
        base_lower = base.lower()
        if index and "index=" not in base_lower:
            base = f"{base.strip()} {index_clause(adapter, index=index, force_index_all=force_index_all)}"
        if "earliest=" not in base_lower:
            base = f"{base.strip()} earliest={earliest_value}"
        if "latest=" not in base_lower:
            base = f"{base.strip()} latest={latest_value}"
        query = f"{base} |{rest}" if sep else base
        return append_head(query.strip(), limit)

    earliest_value, latest_value = resolve_time(time_range, earliest, latest)
    clauses = [
        index_clause(adapter, index=index, force_index_all=force_index_all),
        f"earliest={earliest_value}",
        f"latest={latest_value}",
    ]
    filters = [
        field_filter(["source_ip", "src_ip", "src", "clientip", "client_ip"], source_ip),
        field_filter(["destination_ip", "dest_ip", "dest", "dst"], destination_ip),
        field_filter(["user", "username", "email", "details.email", "details.payload.email", "user.name"], user),
        field_filter(["host", "hostname", "computer_name", "dest_host"], host),
        field_filter(["sourcetype"], sourcetype),
        field_filter(["source"], source, wildcard=True),
        field_filter(["action", "event_category", "message", "signature", "rule_name", "alert.signature"], action, wildcard=True),
        field_filter(["status_code", "status", "details.error.status"], status_code),
        field_filter(["method", "http_method", "request_method"], method),
        field_filter(["path", "uri", "url", "original_url"], path, wildcard=True),
        field_filter(["user_agent", "http_user_agent", "userAgent"], user_agent, wildcard=True),
        field_filter(["authenticated"], authenticated),
        field_filter(["event_category", "category", "event.category"], category, wildcard=True),
        field_filter(["severity", "level", "log_level"], severity),
        field_filter(["_raw", "message", "signature", "rule_name", "action", "event_category"], keyword, wildcard=True),
    ]
    clauses.extend([item for item in filters if item])
    if exclude_keyword:
        escaped = escape_spl_value(exclude_keyword)
        clauses.append(f'NOT (_raw="*{escaped}*" OR message="*{escaped}*")')
    return f"search {' '.join(clauses)} | head {limit}"
