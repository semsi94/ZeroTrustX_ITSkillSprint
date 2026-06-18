from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from fastapi import Request

from config import get_settings


@dataclass(frozen=True)
class ClientIp:
    ip: str
    direct_ip: str
    source: str


def _parse_networks(raw: str):
    networks = []
    for part in (raw or "").split(","):
        value = part.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def _clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip().strip('"').strip("'")
    if not raw or raw.lower() == "unknown":
        return None
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        raw = raw.rsplit(":", 1)[0]
    if raw.startswith("::ffff:"):
        raw = raw[7:]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def _trusted_direct_ip(direct_ip: str) -> bool:
    ip = _clean_ip(direct_ip)
    if not ip:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(parsed in network for network in _parse_networks(get_settings().TRUSTED_PROXY_CIDRS))


def _from_x_forwarded_for(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        ip = _clean_ip(part)
        if ip:
            return ip
    return None


def _from_forwarded(value: str | None) -> str | None:
    if not value:
        return None
    for match in re.finditer(r"(?:^|[;,])\s*for=([^;,]+)", value, flags=re.IGNORECASE):
        ip = _clean_ip(match.group(1))
        if ip:
            return ip
    return None


def get_client_ip(request: Request) -> ClientIp:
    direct_ip = _clean_ip(request.client.host if request.client else None) or "0.0.0.0"
    if not _trusted_direct_ip(direct_ip):
        return ClientIp(ip=direct_ip, direct_ip=direct_ip, source="direct")

    header_candidates = [
        ("x_forwarded_for", _from_x_forwarded_for(request.headers.get("x-forwarded-for"))),
        ("x_real_ip", _clean_ip(request.headers.get("x-real-ip"))),
        ("forwarded", _from_forwarded(request.headers.get("forwarded"))),
    ]
    for source, ip in header_candidates:
        if ip:
            return ClientIp(ip=ip, direct_ip=direct_ip, source=source)
    return ClientIp(ip=direct_ip, direct_ip=direct_ip, source="direct")
