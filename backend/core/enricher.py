import ipaddress
import logging
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from models.asset import Asset

log = logging.getLogger("zerotrustx.enricher")


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


async def resolve_or_create_asset(db: AsyncSession, ip: str, hostname: Optional[str] = None) -> Asset:
    """Look up asset by IP (VARCHAR comparison). Insert placeholder if missing."""
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP: {ip}")

    q = text("SELECT id, hostname, ip, zone, owner, asset_criticality, is_placeholder "
             "FROM assets WHERE ip = :ip LIMIT 1")
    row = (await db.execute(q, {"ip": ip})).mappings().first()

    if row is not None:
        asset = Asset(
            id=row["id"], hostname=row["hostname"], ip=row["ip"], zone=row["zone"],
            owner=row["owner"], asset_criticality=row["asset_criticality"],
            is_placeholder=row["is_placeholder"],
        )
        return asset

    insert = text(
        "INSERT INTO assets (ip, hostname, zone, asset_criticality, is_placeholder) "
        "VALUES (:ip, :hostname, 'unknown', 1, TRUE) "
        "ON CONFLICT (ip) DO NOTHING"
    )
    await db.execute(insert, {"ip": ip, "hostname": hostname or ip})
    await db.flush()

    row = (await db.execute(q, {"ip": ip})).mappings().first()
    if row is None:
        raise RuntimeError(f"Failed to upsert placeholder asset for {ip}")

    return Asset(
        id=row["id"], hostname=row["hostname"], ip=row["ip"], zone=row["zone"],
        owner=row["owner"], asset_criticality=row["asset_criticality"],
        is_placeholder=row["is_placeholder"],
    )
