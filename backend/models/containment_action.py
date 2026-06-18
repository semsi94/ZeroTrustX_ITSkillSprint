import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class ContainmentAction(Base):
    __tablename__ = "containment_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ticket_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(50), default="ip")
    target_value: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    firewall: Mapped[str] = mapped_column(String(50), default="pfSense")
    provider: Mapped[str] = mapped_column(String(80), default="pfSense")
    alias_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requested_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    result_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_response: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
