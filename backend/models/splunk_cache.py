import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class SplunkCachedEvent(Base):
    __tablename__ = "splunk_cached_events"
    __table_args__ = (
        Index("ix_splunk_cache_time", "splunk_time"),
        Index("ix_splunk_cache_source_ip", "source_ip"),
        Index("ix_splunk_cache_destination_ip", "destination_ip"),
        Index("ix_splunk_cache_user_email", "user_email"),
        Index("ix_splunk_cache_host", "host"),
        Index("ix_splunk_cache_action", "action"),
        Index("ix_splunk_cache_index", "index"),
        Index("ix_splunk_cache_sourcetype", "sourcetype"),
        Index("ix_splunk_cache_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    splunk_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ingest_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    index: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sourcetype: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_port: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    outcome: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    original_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_code: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ttl_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
