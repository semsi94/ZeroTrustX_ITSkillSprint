import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Boolean, Text, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    alias: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    initiated_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    initiated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reverted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    output: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rollback_available: Mapped[bool] = mapped_column(Boolean, default=True)

    incident = relationship("Incident", back_populates="response_actions")
