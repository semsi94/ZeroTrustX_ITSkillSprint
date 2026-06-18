"""mitre enterprise matrix completeness

Revision ID: 0014_mitre_enterprise_matrix
Revises: 0013_mitre_attack_analysis
Create Date: 2026-05-01 00:00:14.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0014_mitre_enterprise_matrix"
down_revision = "0013_mitre_attack_analysis"
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
        WHERE table_schema = 'public' AND table_name = :table AND column_name = :column
    """), {"table": table, "column": column}).scalar())


def _add_column_if_missing(table: str, name: str, column) -> None:
    if not _column_exists(table, name):
        op.add_column(table, column)


def upgrade() -> None:
    _add_column_if_missing("mitre_tactics", "matrix_order", sa.Column("matrix_order", sa.Integer(), nullable=True))
    _add_column_if_missing("mitre_techniques", "parent_technique_id", sa.Column("parent_technique_id", sa.String(length=40), nullable=True))
    _add_column_if_missing("mitre_techniques", "revoked", sa.Column("revoked", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False))
    _add_column_if_missing("mitre_techniques", "deprecated", sa.Column("deprecated", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False))

    if not _table_exists("mitre_technique_tactics"):
        op.create_table(
            "mitre_technique_tactics",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("technique_id", sa.String(length=40), nullable=False),
            sa.Column("subtechnique_id", sa.String(length=40), nullable=True),
            sa.Column("tactic_id", sa.String(length=40), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_mitre_technique_tactics_identity
        ON mitre_technique_tactics (technique_id, COALESCE(subtechnique_id, ''), tactic_id)
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_mitre_technique_tactics_tactic_id ON mitre_technique_tactics (tactic_id)")

    if not _table_exists("mitre_sync_state"):
        op.create_table(
            "mitre_sync_state",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("domain", sa.String(length=80), nullable=False),
            sa.Column("version", sa.String(length=80), nullable=True),
            sa.Column("synced_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
            sa.Column("source", sa.Text(), nullable=True),
            sa.Column("technique_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("subtechnique_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("tactic_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("issues", postgresql.JSONB(), nullable=True),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_mitre_sync_state_domain ON mitre_sync_state (domain)")


def downgrade() -> None:
    for table in ("mitre_sync_state", "mitre_technique_tactics"):
        if _table_exists(table):
            op.drop_table(table)
    for table, cols in {
        "mitre_techniques": ("deprecated", "revoked", "parent_technique_id"),
        "mitre_tactics": ("matrix_order",),
    }.items():
        for col in cols:
            if _column_exists(table, col):
                op.drop_column(table, col)
