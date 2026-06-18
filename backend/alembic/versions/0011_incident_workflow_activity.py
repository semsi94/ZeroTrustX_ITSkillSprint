"""incident workflow activity

Revision ID: 0011_incident_workflow_activity
Revises: 0010_soc_tickets
Create Date: 2026-04-30 00:00:01.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0011_incident_workflow_activity"
down_revision = "0010_soc_tickets"
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


def _add_incident_column(name: str, column) -> None:
    if not _column_exists("incidents", name):
        op.add_column("incidents", column)


def upgrade() -> None:
    _add_incident_column("priority", sa.Column("priority", sa.String(length=30), server_default="medium", nullable=False))
    _add_incident_column("queue", sa.Column("queue", sa.String(length=120), nullable=True))
    _add_incident_column("workflow_status", sa.Column("workflow_status", sa.String(length=50), server_default="open", nullable=False))
    _add_incident_column("sla_due_at", sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True))
    _add_incident_column("first_ack_due_at", sa.Column("first_ack_due_at", sa.DateTime(timezone=True), nullable=True))
    _add_incident_column("resolve_due_at", sa.Column("resolve_due_at", sa.DateTime(timezone=True), nullable=True))
    _add_incident_column("escalation_level", sa.Column("escalation_level", sa.Integer(), server_default="0", nullable=False))
    _add_incident_column("requested_action", sa.Column("requested_action", sa.Text(), nullable=True))
    _add_incident_column("resolution_notes", sa.Column("resolution_notes", sa.Text(), nullable=True))
    _add_incident_column("close_reason", sa.Column("close_reason", sa.Text(), nullable=True))

    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_priority ON incidents (priority)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_queue ON incidents (queue)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_workflow_status ON incidents (workflow_status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_sla_due_at ON incidents (sla_due_at)")

    if not _table_exists("incident_comments"):
        op.create_table(
            "incident_comments",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("comment_type", sa.String(length=50), server_default="internal_note", nullable=False),
            sa.Column("created_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_comments_incident_id ON incident_comments (incident_id)")

    if not _table_exists("incident_activity"):
        op.create_table(
            "incident_activity",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("activity_type", sa.String(length=80), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("actor", sa.String(length=255), nullable=True),
            sa.Column("metadata_json", postgresql.JSONB(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_activity_incident_id ON incident_activity (incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_activity_type ON incident_activity (activity_type)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_activity_created_at ON incident_activity (created_at)")


def downgrade() -> None:
    if _table_exists("incident_activity"):
        op.drop_table("incident_activity")
    if _table_exists("incident_comments"):
        op.drop_table("incident_comments")
    for name in (
        "close_reason",
        "resolution_notes",
        "requested_action",
        "escalation_level",
        "resolve_due_at",
        "first_ack_due_at",
        "sla_due_at",
        "workflow_status",
        "queue",
        "priority",
    ):
        if _column_exists("incidents", name):
            op.drop_column("incidents", name)
