"""incident quality cleanup

Revision ID: 0003_incident_quality_cleanup
Revises: 0002_soc_investigation_hardening
Create Date: 2026-04-25 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0003_incident_quality_cleanup"
down_revision = "0002_soc_investigation_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("activation_state", sa.String(length=50), server_default="pending_evidence", nullable=False))
    op.add_column("incidents", sa.Column("is_active", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False))
    op.add_column("incidents", sa.Column("evidence_count", sa.Integer(), server_default="0", nullable=False))
    op.add_column("incidents", sa.Column("category", sa.String(length=100), nullable=True))
    op.add_column("incidents", sa.Column("detection_source", sa.String(length=100), nullable=True))
    op.add_column("incidents", sa.Column("entities", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("incidents", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("approval_status", sa.String(length=50), server_default="approved", nullable=False))
    op.add_column("incidents", sa.Column("approved_by", sa.String(length=255), nullable=True))
    op.add_column("incidents", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("source_ref", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("source_hash", sa.String(length=128), nullable=True))
    op.create_index("ix_incidents_activation_state", "incidents", ["activation_state"])
    op.create_index("ix_incidents_is_active", "incidents", ["is_active"])
    op.create_index("ix_incidents_approval_status", "incidents", ["approval_status"])
    op.create_index("ix_incidents_source_hash", "incidents", ["source_hash"])
    op.execute("UPDATE incidents SET evidence_count = COALESCE((SELECT COUNT(*) FROM evidence e WHERE e.incident_id = incidents.id), 0)")
    op.execute("""
        UPDATE incidents
        SET activation_state = CASE WHEN evidence_count > 0 THEN 'active' ELSE 'pending_evidence' END,
            is_active = evidence_count > 0
    """)


def downgrade() -> None:
    op.drop_index("ix_incidents_source_hash", table_name="incidents")
    op.drop_index("ix_incidents_approval_status", table_name="incidents")
    op.drop_index("ix_incidents_is_active", table_name="incidents")
    op.drop_index("ix_incidents_activation_state", table_name="incidents")
    op.drop_column("incidents", "source_hash")
    op.drop_column("incidents", "source_ref")
    op.drop_column("incidents", "approved_at")
    op.drop_column("incidents", "approved_by")
    op.drop_column("incidents", "approval_status")
    op.drop_column("incidents", "notes")
    op.drop_column("incidents", "entities")
    op.drop_column("incidents", "detection_source")
    op.drop_column("incidents", "category")
    op.drop_column("incidents", "evidence_count")
    op.drop_column("incidents", "is_active")
    op.drop_column("incidents", "activation_state")
