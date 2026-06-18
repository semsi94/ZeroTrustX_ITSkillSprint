import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Integer, Float, Text, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    source_system: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    zone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[int] = mapped_column(Integer, default=2)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    cia_c: Mapped[int] = mapped_column(Integer, default=0)
    cia_i: Mapped[int] = mapped_column(Integer, default=0)
    cia_a: Mapped[int] = mapped_column(Integer, default=0)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    event_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))

    incident = relationship("Incident", back_populates="alerts")
