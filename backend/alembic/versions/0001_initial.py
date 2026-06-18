"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("username", sa.String(100), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("hostname", sa.String(255)),
        sa.Column("ip", sa.String(45), nullable=False, unique=True),
        sa.Column("zone", sa.String(50), server_default="unknown"),
        sa.Column("owner", sa.String(255)),
        sa.Column("asset_criticality", sa.Integer, server_default="1"),
        sa.Column("is_placeholder", sa.Boolean, server_default=sa.text("FALSE")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.CheckConstraint("asset_criticality BETWEEN 1 AND 5", name="asset_criticality_range"),
    )

    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("severity", sa.Integer, server_default="2"),
        sa.Column("confidence", sa.Float, server_default="0.5"),
        sa.Column("status", sa.String(50), server_default="new"),
        sa.Column("cia_c", sa.Integer, server_default="0"),
        sa.Column("cia_i", sa.Integer, server_default="0"),
        sa.Column("cia_a", sa.Integer, server_default="0"),
        sa.Column("mitre_tactic", sa.String(100)),
        sa.Column("mitre_technique", sa.String(100)),
        sa.Column("primary_asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="SET NULL")),
        sa.Column("response_level", sa.Integer, server_default="1"),
        sa.Column("source_systems", postgresql.ARRAY(sa.Text)),
        sa.Column("priority_score", sa.Integer, server_default="0"),
        sa.Column("is_false_positive", sa.Boolean, server_default=sa.text("FALSE")),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("triaged_at", sa.DateTime(timezone=True)),
        sa.Column("contained_at", sa.DateTime(timezone=True)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("analyst_notes", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.CheckConstraint("severity BETWEEN 1 AND 5", name="incident_severity_range"),
        sa.CheckConstraint("cia_c BETWEEN 0 AND 2", name="incident_cia_c_range"),
        sa.CheckConstraint("cia_i BETWEEN 0 AND 2", name="incident_cia_i_range"),
        sa.CheckConstraint("cia_a BETWEEN 0 AND 2", name="incident_cia_a_range"),
        sa.CheckConstraint("response_level BETWEEN 1 AND 3", name="incident_response_level_range"),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE")),
        sa.Column("source_system", sa.String(50)),
        sa.Column("event_type", sa.String(100)),
        sa.Column("src_ip", sa.String(45)),
        sa.Column("dest_ip", sa.String(45)),
        sa.Column("username", sa.String(255)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("signature", sa.Text),
        sa.Column("category", sa.String(100)),
        sa.Column("zone", sa.String(50)),
        sa.Column("severity", sa.Integer, server_default="2"),
        sa.Column("confidence", sa.Float, server_default="0.5"),
        sa.Column("cia_c", sa.Integer, server_default="0"),
        sa.Column("cia_i", sa.Integer, server_default="0"),
        sa.Column("cia_a", sa.Integer, server_default="0"),
        sa.Column("mitre_tactic", sa.String(100)),
        sa.Column("raw_ref", sa.Text),
        sa.Column("raw_payload", postgresql.JSONB),
        sa.Column("event_time", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_alerts_incident", "alerts", ["incident_id"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])
    op.create_index("ix_alerts_dest_ip", "alerts", ["dest_ip"])
    op.create_index("ix_alerts_event_time", "alerts", ["event_time"])

    op.create_table(
        "response_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE")),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("alias", sa.String(100)),
        sa.Column("status", sa.String(50), server_default="pending"),
        sa.Column("initiated_by", sa.String(255)),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("initiated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("reverted_at", sa.DateTime(timezone=True)),
        sa.Column("output", postgresql.JSONB),
        sa.Column("error_message", sa.Text),
        sa.Column("rollback_available", sa.Boolean, server_default=sa.text("TRUE")),
    )
    op.create_index("ix_response_actions_incident", "response_actions", ["incident_id"])
    op.create_index("ix_response_actions_status", "response_actions", ["status"])

    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE")),
        sa.Column("type", sa.String(50)),
        sa.Column("path_or_ref", sa.Text),
        sa.Column("hash", sa.String(64)),
        sa.Column("collected_by", sa.String(255)),
        sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("raw_data", postgresql.JSONB),
    )
    op.create_index("ix_evidence_incident", "evidence", ["incident_id"])


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("response_actions")
    op.drop_table("alerts")
    op.drop_table("incidents")
    op.drop_table("assets")
    op.drop_table("users")
