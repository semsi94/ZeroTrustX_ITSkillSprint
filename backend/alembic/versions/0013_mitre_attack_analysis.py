"""mitre attack analysis

Revision ID: 0013_mitre_attack_analysis
Revises: 0012_soc_backend_boundaries
Create Date: 2026-04-30 00:00:03.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0013_mitre_attack_analysis"
down_revision = "0012_soc_backend_boundaries"
branch_labels = None
depends_on = None


def _table_exists(table: str) -> bool:
    conn = op.get_bind()
    return bool(conn.execute(sa.text("""
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = :table
    """), {"table": table}).scalar())


def _column_exists(table: str, column: str) -> bool:
    conn = op.get_bind()
    return bool(conn.execute(sa.text("""
        SELECT 1 FROM information_schema.columns
        WHERE table_name = :table AND column_name = :column
    """), {"table": table, "column": column}).scalar())


def _add_column_if_missing(table: str, name: str, column) -> None:
    if not _column_exists(table, name):
        op.add_column(table, column)


def upgrade() -> None:
    if not _table_exists("mitre_tactics"):
        op.create_table(
            "mitre_tactics",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("tactic_id", sa.String(length=40), nullable=False),
            sa.Column("short_name", sa.String(length=120), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("attack_url", sa.Text(), nullable=True),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_mitre_tactics_tactic_id ON mitre_tactics (tactic_id)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_mitre_tactics_short_name ON mitre_tactics (short_name)")

    if not _table_exists("mitre_techniques"):
        op.create_table(
            "mitre_techniques",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("technique_id", sa.String(length=40), nullable=False),
            sa.Column("subtechnique_id", sa.String(length=40), nullable=True),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("tactic_id", sa.String(length=40), nullable=True),
            sa.Column("tactic_refs", postgresql.JSONB(), nullable=True),
            sa.Column("platforms", postgresql.JSONB(), nullable=True),
            sa.Column("data_sources", postgresql.JSONB(), nullable=True),
            sa.Column("detection", sa.Text(), nullable=True),
            sa.Column("mitigation_refs", postgresql.JSONB(), nullable=True),
            sa.Column("attack_url", sa.Text(), nullable=True),
            sa.Column("is_subtechnique", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_mitre_techniques_identity ON mitre_techniques (technique_id, COALESCE(subtechnique_id, ''), COALESCE(tactic_id, ''))")
    op.execute("CREATE INDEX IF NOT EXISTS ix_mitre_techniques_tactic_id ON mitre_techniques (tactic_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_mitre_techniques_name ON mitre_techniques (name)")

    _add_column_if_missing("incident_mitre_links", "subtechnique_id", sa.Column("subtechnique_id", sa.String(length=80), nullable=True))
    _add_column_if_missing("incident_mitre_links", "confidence_score", sa.Column("confidence_score", sa.Integer(), nullable=True))
    _add_column_if_missing("incident_mitre_links", "reason", sa.Column("reason", sa.Text(), nullable=True))
    _add_column_if_missing("incident_mitre_links", "matched_fields", sa.Column("matched_fields", postgresql.JSONB(), nullable=True))
    _add_column_if_missing("incident_mitre_links", "matched_evidence_ids", sa.Column("matched_evidence_ids", postgresql.JSONB(), nullable=True))
    _add_column_if_missing("incident_mitre_links", "created_by", sa.Column("created_by", sa.String(length=255), nullable=True))
    _add_column_if_missing("incident_mitre_links", "updated_at", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False))
    op.execute("UPDATE incident_mitre_links SET confidence_score = COALESCE(confidence_score, ROUND(COALESCE(confidence, 0) * 100)::int), updated_at = COALESCE(updated_at, NOW())")
    op.execute("DROP INDEX IF EXISTS ux_incident_mitre_links_unique")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_mitre_links_identity ON incident_mitre_links (incident_id, technique_id, COALESCE(subtechnique_id, ''), COALESCE(tactic_id, ''))")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_mitre_links_subtechnique_id ON incident_mitre_links (subtechnique_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_mitre_links_confidence_score ON incident_mitre_links (confidence_score)")

    if not _table_exists("evidence_mitre_links"):
        op.create_table(
            "evidence_mitre_links",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tactic_id", sa.String(length=80), nullable=True),
            sa.Column("technique_id", sa.String(length=80), nullable=False),
            sa.Column("subtechnique_id", sa.String(length=80), nullable=True),
            sa.Column("confidence_score", sa.Integer(), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_mitre_links_unique ON evidence_mitre_links (evidence_id, technique_id, COALESCE(subtechnique_id, ''))")
    op.execute("CREATE INDEX IF NOT EXISTS ix_evidence_mitre_links_evidence_id ON evidence_mitre_links (evidence_id)")


def downgrade() -> None:
    if _table_exists("evidence_mitre_links"):
        op.drop_table("evidence_mitre_links")
    for name in ("updated_at", "created_by", "matched_evidence_ids", "matched_fields", "reason", "confidence_score", "subtechnique_id"):
        if _column_exists("incident_mitre_links", name):
            op.drop_column("incident_mitre_links", name)
    for table in ("mitre_techniques", "mitre_tactics"):
        if _table_exists(table):
            op.drop_table(table)
