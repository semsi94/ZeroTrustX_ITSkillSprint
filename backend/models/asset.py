import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Integer, Boolean, CheckConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("asset_criticality BETWEEN 1 AND 5", name="asset_criticality_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    zone: Mapped[str] = mapped_column(String(50), default="unknown")
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asset_criticality: Mapped[int] = mapped_column(Integer, default=1)
    is_placeholder: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
