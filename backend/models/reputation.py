import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class IpReputation(Base):
    __tablename__ = "ip_reputation"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    overall_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_verdict: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown", index=True)
    abuseipdb_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    abuseipdb_total_reports: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    abuseipdb_country_code: Mapped[Optional[str]] = mapped_column(String(12), nullable=True)
    abuseipdb_usage_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    abuseipdb_isp: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    abuseipdb_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    abuseipdb_last_reported_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    virustotal_malicious: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    virustotal_suspicious: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    virustotal_harmless: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    virustotal_undetected: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    virustotal_reputation: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    virustotal_country: Mapped[Optional[str]] = mapped_column(String(12), nullable=True)
    virustotal_as_owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    virustotal_network: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider_sources: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    raw_abuseipdb: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    raw_virustotal: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class IpObservation(Base):
    __tablename__ = "ip_observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_system: Mapped[str] = mapped_column(String(80), nullable=False, default="unknown")
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    event_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    field_name: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class IncidentIpReputationLink(Base):
    __tablename__ = "incident_ip_reputation_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reputation_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("ip_reputation.id", ondelete="SET NULL"), nullable=True)
    verdict: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown")
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_tools: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
