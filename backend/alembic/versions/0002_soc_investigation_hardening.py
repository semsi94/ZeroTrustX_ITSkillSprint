"""soc investigation hardening

Revision ID: 0002_soc_investigation_hardening
Revises: 0001_initial
Create Date: 2026-04-25

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_soc_investigation_hardening"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    exists = bind.execute(sa.text("""
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = :table AND column_name = :column
    """), {"table": table, "column": column.name}).first()
    if not exists:
        op.add_column(table, column)


def upgrade() -> None:
    _add_column_if_missing("incidents", sa.Column("description", sa.Text(), nullable=True))
    _add_column_if_missing("incidents", sa.Column("source", sa.String(length=100), server_default="analyst"))
    _add_column_if_missing("incidents", sa.Column("owner", sa.String(length=255), nullable=True))
    _add_column_if_missing("incidents", sa.Column("linked_splunk_alert_id", sa.Text(), nullable=True))
    _add_column_if_missing("incidents", sa.Column("linked_splunk_report_id", sa.Text(), nullable=True))
    _add_column_if_missing("incidents", sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=True))
    _add_column_if_missing("incidents", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")))

    _add_column_if_missing("evidence", sa.Column("event_hash", sa.String(length=64), nullable=True))
    _add_column_if_missing("evidence", sa.Column("event_time", sa.DateTime(timezone=True), nullable=True))
    _add_column_if_missing("evidence", sa.Column("source", sa.String(length=100), nullable=True))
    _add_column_if_missing("evidence", sa.Column("index", sa.String(length=255), nullable=True))
    _add_column_if_missing("evidence", sa.Column("sourcetype", sa.String(length=255), nullable=True))
    _add_column_if_missing("evidence", sa.Column("host", sa.String(length=255), nullable=True))
    _add_column_if_missing("evidence", sa.Column("source_ip", sa.String(length=45), nullable=True))
    _add_column_if_missing("evidence", sa.Column("destination_ip", sa.String(length=45), nullable=True))
    _add_column_if_missing("evidence", sa.Column("user_email", sa.String(length=255), nullable=True))
    _add_column_if_missing("evidence", sa.Column("action", sa.String(length=255), nullable=True))
    _add_column_if_missing("evidence", sa.Column("message", sa.Text(), nullable=True))
    _add_column_if_missing("evidence", sa.Column("raw_event", postgresql.JSONB(astext_type=sa.Text()), nullable=True))

    op.create_table(
        "splunk_cached_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("splunk_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingest_time", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("index", sa.String(length=255), nullable=True),
        sa.Column("sourcetype", sa.String(length=255), nullable=True),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_port", sa.String(length=32), nullable=True),
        sa.Column("user_email", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=255), nullable=True),
        sa.Column("category", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=255), nullable=True),
        sa.Column("method", sa.String(length=32), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("original_url", sa.Text(), nullable=True),
        sa.Column("status_code", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("raw_event", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ttl_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("event_hash", name="uq_splunk_cached_events_hash"),
    )
    for name, cols in {
        "ix_splunk_cache_time": ["splunk_time"],
        "ix_splunk_cache_source_ip": ["source_ip"],
        "ix_splunk_cache_destination_ip": ["destination_ip"],
        "ix_splunk_cache_user_email": ["user_email"],
        "ix_splunk_cache_host": ["host"],
        "ix_splunk_cache_action": ["action"],
        "ix_splunk_cache_index": ["index"],
        "ix_splunk_cache_sourcetype": ["sourcetype"],
        "ix_splunk_cache_severity": ["severity"],
        "ix_evidence_event_hash": ["event_hash"],
    }.items():
        table = "evidence" if name == "ix_evidence_event_hash" else "splunk_cached_events"
        op.create_index(name, table, cols, if_not_exists=True)


def downgrade() -> None:
    op.drop_table("splunk_cached_events")
