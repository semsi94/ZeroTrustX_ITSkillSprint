import uuid
from datetime import datetime
from typing import Optional, List
import uuid

from sqlalchemy import String, DateTime, Integer, Float, Boolean, Text, ForeignKey, CheckConstraint, text
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("severity BETWEEN 1 AND 5", name="incident_severity_range"),
        CheckConstraint("cia_c BETWEEN 0 AND 2", name="incident_cia_c_range"),
        CheckConstraint("cia_i BETWEEN 0 AND 2", name="incident_cia_i_range"),
        CheckConstraint("cia_a BETWEEN 0 AND 2", name="incident_cia_a_range"),
        CheckConstraint("response_level BETWEEN 1 AND 3", name="incident_response_level_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[int] = mapped_column(Integer, default=2)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(50), default="new", index=True)
    activation_state: Mapped[str] = mapped_column(String(50), default="pending_evidence", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(100), default="analyst")
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    linked_splunk_alert_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    linked_splunk_report_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    entities: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approval_status: Mapped[str] = mapped_column(String(50), default="approved", index=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    source_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    dedup_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    analyst_verdict: Mapped[str] = mapped_column(String(50), default="undecided", index=True)
    verdict_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verdict_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    verdict_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cia_c: Mapped[int] = mapped_column(Integer, default=0)
    cia_i: Mapped[int] = mapped_column(Integer, default=0)
    cia_a: Mapped[int] = mapped_column(Integer, default=0)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    mitre_technique_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mitre_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mitre_mapping_source: Mapped[str] = mapped_column(String(50), default="auto")
    primary_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    response_level: Mapped[int] = mapped_column(Integer, default=1)
    source_systems: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[str] = mapped_column(String(30), default="medium", index=True)
    queue: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    workflow_status: Mapped[str] = mapped_column(String(50), default="open", index=True)
    sla_due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    first_ack_due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolve_due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)
    requested_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    close_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), index=True)
    triaged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))

    primary_asset = relationship("Asset", foreign_keys=[primary_asset_id], lazy="joined")
    alerts = relationship("Alert", back_populates="incident", cascade="all, delete-orphan")
    response_actions = relationship("ResponseAction", back_populates="incident", cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    tickets = relationship("Ticket", back_populates="incident")
