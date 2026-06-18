import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    path_or_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    event_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_system: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    query_sid: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    search_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    index: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sourcetype: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    collected_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    collector_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    raw_data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    incident = relationship("Incident", back_populates="evidence_items")
