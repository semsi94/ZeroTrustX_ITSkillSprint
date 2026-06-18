"""soc backend boundaries

Revision ID: 0012_soc_backend_boundaries
Revises: 0011_incident_workflow_activity
Create Date: 2026-04-30 00:00:02.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0012_soc_backend_boundaries"
down_revision = "0011_incident_workflow_activity"
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
    for name, column in (
        ("source_system", sa.Column("source_system", sa.String(length=100), nullable=True)),
        ("source_ref", sa.Column("source_ref", sa.Text(), nullable=True)),
        ("query_sid", sa.Column("query_sid", sa.String(length=255), nullable=True)),
        ("search_id", sa.Column("search_id", sa.String(length=255), nullable=True)),
        ("content_hash", sa.Column("content_hash", sa.String(length=64), nullable=True)),
        ("collector_id", sa.Column("collector_id", sa.String(length=120), nullable=True)),
    ):
        _add_column_if_missing("evidence", name, column)
    op.execute("CREATE INDEX IF NOT EXISTS ix_evidence_content_hash ON evidence (content_hash)")
    op.execute("UPDATE evidence SET source_system = COALESCE(source_system, source), content_hash = COALESCE(content_hash, event_hash, hash), source_ref = COALESCE(source_ref, path_or_ref) WHERE source_system IS NULL OR content_hash IS NULL OR source_ref IS NULL")

    for name, column in (
        ("target_type", sa.Column("target_type", sa.String(length=50), server_default="ip", nullable=False)),
        ("target_value", sa.Column("target_value", sa.String(length=255), nullable=True)),
        ("provider", sa.Column("provider", sa.String(length=80), server_default="pfSense", nullable=False)),
    ):
        _add_column_if_missing("containment_actions", name, column)
    op.execute("CREATE INDEX IF NOT EXISTS ix_containment_actions_target_value ON containment_actions (target_value)")
    op.execute("UPDATE containment_actions SET target_type = COALESCE(target_type, 'ip'), target_value = COALESCE(target_value, target_ip), provider = COALESCE(provider, firewall, 'pfSense')")

    if not _table_exists("external_alerts"):
        op.create_table(
            "external_alerts",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("source_system", sa.String(length=80), nullable=False),
            sa.Column("source_event_id", sa.String(length=255), nullable=True),
            sa.Column("rule_name", sa.String(length=500), nullable=False),
            sa.Column("severity", sa.String(length=40), nullable=True),
            sa.Column("raw_json", postgresql.JSONB(), nullable=True),
            sa.Column("dedupe_key", sa.String(length=128), nullable=False),
            sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
            sa.Column("linked_incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_external_alerts_dedupe_key ON external_alerts (dedupe_key)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_external_alerts_source_system ON external_alerts (source_system)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_external_alerts_source_event_id ON external_alerts (source_event_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_external_alerts_linked_incident_id ON external_alerts (linked_incident_id)")

    if not _table_exists("observables"):
        op.create_table(
            "observables",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("type", sa.String(length=50), nullable=False),
            sa.Column("value", sa.Text(), nullable=False),
            sa.Column("is_ioc", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False),
            sa.Column("is_sighted", sa.Boolean(), server_default=sa.text("TRUE"), nullable=False),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_observables_incident_type_value ON observables (incident_id, type, lower(value))")
    op.execute("CREATE INDEX IF NOT EXISTS ix_observables_incident_id ON observables (incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_observables_type ON observables (type)")

    if not _table_exists("incident_mitre_links"):
        op.create_table(
            "incident_mitre_links",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tactic_id", sa.String(length=80), nullable=True),
            sa.Column("technique_id", sa.String(length=80), nullable=False),
            sa.Column("technique_name", sa.String(length=255), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("mapped_by", sa.String(length=255), nullable=True),
            sa.Column("mapping_source", sa.String(length=50), server_default="manual", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_mitre_links_unique ON incident_mitre_links (incident_id, technique_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incident_mitre_links_incident_id ON incident_mitre_links (incident_id)")

    if not _table_exists("event_outbox"):
        op.create_table(
            "event_outbox",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("event_type", sa.String(length=120), nullable=False),
            sa.Column("aggregate_type", sa.String(length=80), nullable=False),
            sa.Column("aggregate_id", sa.String(length=120), nullable=False),
            sa.Column("payload_json", postgresql.JSONB(), nullable=True),
            sa.Column("status", sa.String(length=40), server_default="pending", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_event_outbox_status ON event_outbox (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_event_outbox_aggregate ON event_outbox (aggregate_type, aggregate_id)")

    if not _table_exists("idempotency_keys"):
        op.create_table(
            "idempotency_keys",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("key", sa.String(length=255), nullable=False),
            sa.Column("scope", sa.String(length=80), nullable=False),
            sa.Column("request_hash", sa.String(length=128), nullable=True),
            sa.Column("response_hash", sa.String(length=128), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_idempotency_keys_scope_key ON idempotency_keys (scope, key)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_idempotency_keys_expires_at ON idempotency_keys (expires_at)")

    if not _table_exists("audit_log"):
        op.create_table(
            "audit_log",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("actor_id", sa.String(length=120), nullable=True),
            sa.Column("action", sa.String(length=120), nullable=False),
            sa.Column("object_type", sa.String(length=80), nullable=False),
            sa.Column("object_id", sa.String(length=120), nullable=True),
            sa.Column("outcome", sa.String(length=40), nullable=False),
            sa.Column("ip", sa.String(length=80), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_action ON audit_log (action)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_object ON audit_log (object_type, object_id)")

    if not _table_exists("playbooks"):
        op.create_table(
            "playbooks",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("trigger_type", sa.String(length=80), nullable=False),
            sa.Column("enabled", sa.Boolean(), server_default=sa.text("TRUE"), nullable=False),
            sa.Column("requires_approval", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False),
            sa.Column("version", sa.String(length=40), server_default="1", nullable=False),
        )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_playbooks_name ON playbooks (name)")

    if not _table_exists("playbook_runs"):
        op.create_table(
            "playbook_runs",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("playbook_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("status", sa.String(length=40), server_default="requested", nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("idempotency_key", sa.String(length=255), nullable=True),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_playbook_runs_incident_id ON playbook_runs (incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_playbook_runs_status ON playbook_runs (status)")

    if not _table_exists("connector_credentials"):
        op.create_table(
            "connector_credentials",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("provider", sa.String(length=80), nullable=False),
            sa.Column("secret_ref", sa.String(length=255), nullable=False),
            sa.Column("scopes", postgresql.JSONB(), nullable=True),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_connector_credentials_provider ON connector_credentials (provider)")

    if not _table_exists("approval_requests"):
        op.create_table(
            "approval_requests",
            sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
            sa.Column("action_type", sa.String(length=80), nullable=False),
            sa.Column("target_ref", sa.String(length=255), nullable=False),
            sa.Column("requested_by", sa.String(length=255), nullable=True),
            sa.Column("approved_by", sa.String(length=255), nullable=True),
            sa.Column("status", sa.String(length=40), server_default="pending", nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_approval_requests_status ON approval_requests (status)")


def downgrade() -> None:
    for table in (
        "approval_requests",
        "connector_credentials",
        "playbook_runs",
        "playbooks",
        "audit_log",
        "idempotency_keys",
        "event_outbox",
        "incident_mitre_links",
        "observables",
        "external_alerts",
    ):
        if _table_exists(table):
            op.drop_table(table)
    for table, columns in {
        "containment_actions": ("provider", "target_value", "target_type"),
        "evidence": ("collector_id", "content_hash", "search_id", "query_sid", "source_ref", "source_system"),
    }.items():
        for column in columns:
            if _column_exists(table, column):
                op.drop_column(table, column)
