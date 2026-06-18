import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class ExternalAlert(Base):
    __tablename__ = "external_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    source_system: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    source_event_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    raw_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    linked_incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )


class Observable(Base):
    __tablename__ = "observables"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    is_ioc: Mapped[bool] = mapped_column(Boolean, server_default=text("FALSE"), nullable=False)
    is_sighted: Mapped[bool] = mapped_column(Boolean, server_default=text("TRUE"), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))


class IncidentMitreLink(Base):
    __tablename__ = "incident_mitre_links"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tactic_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    technique_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    subtechnique_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    technique_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    confidence_score: Mapped[Optional[int]] = mapped_column(nullable=True)
    mapped_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mapping_source: Mapped[str] = mapped_column(String(50), server_default="manual", nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    matched_fields: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    matched_evidence_ids: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))


class MitreTactic(Base):
    __tablename__ = "mitre_tactics"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tactic_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True)
    short_name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attack_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    technique_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    subtechnique_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tactic_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    tactic_refs: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    platforms: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    data_sources: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    detection: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitigation_refs: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    attack_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, server_default=text("FALSE"), nullable=False)


class EvidenceMitreLink(Base):
    __tablename__ = "evidence_mitre_links"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tactic_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    technique_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    subtechnique_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    confidence_score: Mapped[int] = mapped_column(nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))


class EventOutbox(Base):
    __tablename__ = "event_outbox"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    event_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    aggregate_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    aggregate_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    payload_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(String(40), server_default="pending", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    request_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    response_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    object_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    ip: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    trigger_type: Mapped[str] = mapped_column(String(80), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("TRUE"), nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, server_default=text("FALSE"), nullable=False)
    version: Mapped[str] = mapped_column(String(40), server_default="1", nullable=False)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(40), server_default="requested", nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)


class ConnectorCredential(Base):
    __tablename__ = "connector_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    provider: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    secret_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    action_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_ref: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    requested_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(40), server_default="pending", nullable=False, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"))
