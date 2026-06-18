"""soc case workflow

Revision ID: 0004_soc_case_workflow
Revises: 0003_incident_quality_cleanup
Create Date: 2026-04-25 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_soc_case_workflow"
down_revision = "0003_incident_quality_cleanup"
branch_labels = None
depends_on = None


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    conn = op.get_bind()
    exists = conn.execute(sa.text("""
        SELECT 1 FROM information_schema.columns
        WHERE table_name = :table AND column_name = :column
    """), {"table": table, "column": column.name}).scalar()
    if not exists:
        op.add_column(table, column)


def upgrade() -> None:
    _add_column_if_missing("incidents", sa.Column("dedup_key", sa.String(length=128), nullable=True))
    _add_column_if_missing("incidents", sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False))
    _add_column_if_missing("incidents", sa.Column("analyst_verdict", sa.String(length=50), server_default="undecided", nullable=False))
    _add_column_if_missing("incidents", sa.Column("verdict_reason", sa.Text(), nullable=True))
    _add_column_if_missing("incidents", sa.Column("verdict_by", sa.String(length=255), nullable=True))
    _add_column_if_missing("incidents", sa.Column("verdict_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_if_missing("incidents", sa.Column("mitre_technique_id", sa.String(length=50), nullable=True))
    _add_column_if_missing("incidents", sa.Column("mitre_technique_name", sa.String(length=255), nullable=True))
    _add_column_if_missing("incidents", sa.Column("mitre_confidence", sa.Float(), nullable=True))
    _add_column_if_missing("incidents", sa.Column("mitre_mapping_source", sa.String(length=50), server_default="auto", nullable=False))

    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_dedup_key ON incidents (dedup_key)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_verdict ON incidents (analyst_verdict)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS containment_actions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NULL REFERENCES incidents(id) ON DELETE SET NULL,
            action_type VARCHAR(50) NOT NULL,
            target_ip VARCHAR(45) NOT NULL,
            firewall VARCHAR(50) DEFAULT 'pfSense',
            alias_name VARCHAR(100),
            reason TEXT,
            requested_by VARCHAR(255),
            requested_at TIMESTAMPTZ DEFAULT NOW(),
            executed_at TIMESTAMPTZ,
            status VARCHAR(50) DEFAULT 'pending',
            result_message TEXT,
            raw_response JSONB
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_containment_actions_incident ON containment_actions (incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_containment_actions_target ON containment_actions (target_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_containment_actions_status ON containment_actions (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_containment_actions_action_type ON containment_actions (action_type)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_search_cache (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            cache_key VARCHAR(128) UNIQUE NOT NULL,
            query TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            result_count INTEGER DEFAULT 0,
            normalized_events JSONB
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigation_cache_key ON investigation_search_cache (cache_key)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigation_cache_expires ON investigation_search_cache (expires_at)")


def downgrade() -> None:
    op.drop_table("investigation_search_cache")
    op.drop_table("containment_actions")
    op.drop_index("ix_incidents_verdict", table_name="incidents")
    op.drop_index("ix_incidents_dedup_key", table_name="incidents")
    for column in [
        "mitre_mapping_source",
        "mitre_confidence",
        "mitre_technique_name",
        "mitre_technique_id",
        "verdict_at",
        "verdict_by",
        "verdict_reason",
        "analyst_verdict",
        "occurrence_count",
        "dedup_key",
    ]:
        op.drop_column("incidents", column)
