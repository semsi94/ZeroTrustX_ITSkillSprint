"""soc tickets

Revision ID: 0010_soc_tickets
Revises: 0009_local_auth_cleanup
Create Date: 2026-04-30 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0010_soc_tickets"
down_revision = "0009_local_auth_cleanup"
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


def upgrade() -> None:
    if not _table_exists("tickets"):
        op.create_table(
            "tickets",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("ticket_number", sa.String(length=40), nullable=False),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("title", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("queue", sa.String(length=120), nullable=True),
            sa.Column("assignee", sa.String(length=255), nullable=True),
            sa.Column("priority", sa.String(length=30), server_default="medium", nullable=False),
            sa.Column("status", sa.String(length=40), server_default="open", nullable=False),
            sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("escalation_level", sa.Integer(), server_default="0", nullable=False),
            sa.Column("requested_action", sa.Text(), nullable=True),
            sa.Column("resolution_notes", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_tickets_ticket_number ON tickets (ticket_number)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_incident_id ON tickets (incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_status ON tickets (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_priority ON tickets (priority)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_queue ON tickets (queue)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_assignee ON tickets (assignee)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_sla_due_at ON tickets (sla_due_at)")

    if not _column_exists("containment_actions", "ticket_id"):
        op.add_column("containment_actions", sa.Column("ticket_id", postgresql.UUID(as_uuid=True), nullable=True))
        op.create_foreign_key(
            "fk_containment_actions_ticket_id_tickets",
            "containment_actions",
            "tickets",
            ["ticket_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_containment_actions_ticket_id ON containment_actions (ticket_id)")

    if not _column_exists("containment_actions", "approved_by"):
        op.add_column("containment_actions", sa.Column("approved_by", sa.String(length=255), nullable=True))


def downgrade() -> None:
    if _column_exists("containment_actions", "approved_by"):
        op.drop_column("containment_actions", "approved_by")
    if _column_exists("containment_actions", "ticket_id"):
        op.execute("DROP INDEX IF EXISTS ix_containment_actions_ticket_id")
        op.drop_column("containment_actions", "ticket_id")
    if _table_exists("tickets"):
        op.drop_table("tickets")
