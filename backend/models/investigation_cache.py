import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class InvestigationSearchCache(Base):
    __tablename__ = "investigation_search_cache"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    cache_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    normalized_events: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
