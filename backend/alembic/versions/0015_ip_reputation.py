"""ip reputation

Revision ID: 0015_ip_reputation
Revises: 0014_mitre_enterprise_matrix
Create Date: 2026-05-01 02:30:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0015_ip_reputation"
down_revision = "0014_mitre_enterprise_matrix"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ip_reputation",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("overall_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("overall_verdict", sa.String(length=30), nullable=False, server_default="unknown"),
        sa.Column("abuseipdb_score", sa.Integer(), nullable=True),
        sa.Column("abuseipdb_total_reports", sa.Integer(), nullable=True),
        sa.Column("abuseipdb_country_code", sa.String(length=12), nullable=True),
        sa.Column("abuseipdb_usage_type", sa.String(length=255), nullable=True),
        sa.Column("abuseipdb_isp", sa.String(length=255), nullable=True),
        sa.Column("abuseipdb_domain", sa.String(length=255), nullable=True),
        sa.Column("abuseipdb_last_reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("virustotal_malicious", sa.Integer(), nullable=True),
        sa.Column("virustotal_suspicious", sa.Integer(), nullable=True),
        sa.Column("virustotal_harmless", sa.Integer(), nullable=True),
        sa.Column("virustotal_undetected", sa.Integer(), nullable=True),
        sa.Column("virustotal_reputation", sa.Integer(), nullable=True),
        sa.Column("virustotal_country", sa.String(length=12), nullable=True),
        sa.Column("virustotal_as_owner", sa.String(length=255), nullable=True),
        sa.Column("virustotal_network", sa.String(length=255), nullable=True),
        sa.Column("provider_sources", postgresql.JSONB(), nullable=True),
        sa.Column("raw_abuseipdb", postgresql.JSONB(), nullable=True),
        sa.Column("raw_virustotal", postgresql.JSONB(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.create_index("ux_ip_reputation_ip_address", "ip_reputation", ["ip_address"], unique=True)
    op.create_index("ix_ip_reputation_expires_at", "ip_reputation", ["expires_at"])
    op.create_index("ix_ip_reputation_overall_verdict", "ip_reputation", ["overall_verdict"])

    op.create_table(
        "ip_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("source_system", sa.String(length=80), nullable=False, server_default="unknown"),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_hash", sa.String(length=128), nullable=True),
        sa.Column("field_name", sa.String(length=80), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_ip_observations_ip_address", "ip_observations", ["ip_address"])
    op.create_index("ix_ip_observations_incident_id", "ip_observations", ["incident_id"])
    op.create_index("ix_ip_observations_evidence_id", "ip_observations", ["evidence_id"])
    op.create_index("ux_ip_observation_dedupe", "ip_observations", ["ip_address", "source_system", "incident_id", "evidence_id", "event_hash", "field_name"], unique=True, postgresql_where=sa.text("event_hash IS NOT NULL"))

    op.create_table(
        "incident_ip_reputation_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("reputation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ip_reputation.id", ondelete="SET NULL"), nullable=True),
        sa.Column("verdict", sa.String(length=30), nullable=False, server_default="unknown"),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_tools", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("ix_incident_ip_reputation_links_incident_id", "incident_ip_reputation_links", ["incident_id"])
    op.create_index("ix_incident_ip_reputation_links_ip_address", "incident_ip_reputation_links", ["ip_address"])
    op.create_index("ux_incident_ip_reputation_link", "incident_ip_reputation_links", ["incident_id", "ip_address"], unique=True)


def downgrade() -> None:
    op.drop_table("incident_ip_reputation_links")
    op.drop_table("ip_observations")
    op.drop_table("ip_reputation")
