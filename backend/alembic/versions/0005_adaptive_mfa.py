"""adaptive mfa

Revision ID: 0005_adaptive_mfa
Revises: 0004_soc_case_workflow
Create Date: 2026-04-26 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_adaptive_mfa"
down_revision = "0004_soc_case_workflow"
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
    _add_column_if_missing("users", sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    _add_column_if_missing("users", sa.Column("mfa_secret_encrypted", sa.String(), nullable=True))
    _add_column_if_missing("users", sa.Column("mfa_pending_secret_encrypted", sa.String(), nullable=True))
    _add_column_if_missing("users", sa.Column("mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_if_missing("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_if_missing("users", sa.Column("last_login_ip", sa.String(length=45), nullable=True))
    _add_column_if_missing("users", sa.Column("last_login_user_agent_hash", sa.String(length=64), nullable=True))
    _add_column_if_missing("users", sa.Column("last_login_country", sa.String(length=100), nullable=True))
    _add_column_if_missing("users", sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False))
    _add_column_if_missing("users", sa.Column("last_failed_login_at", sa.DateTime(timezone=True), nullable=True))
    _add_column_if_missing("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))

    op.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            username_or_email VARCHAR(255),
            ip_address VARCHAR(45),
            user_agent TEXT,
            user_agent_hash VARCHAR(64),
            country VARCHAR(100),
            city VARCHAR(100),
            success BOOLEAN DEFAULT FALSE,
            risk_score INTEGER DEFAULT 0,
            risk_reasons JSONB,
            mfa_required BOOLEAN DEFAULT FALSE,
            mfa_success BOOLEAN NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_login_attempts_user ON login_attempts (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_login_attempts_created ON login_attempts (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_login_attempts_ip ON login_attempts (ip_address)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            device_fingerprint_hash VARCHAR(64) NOT NULL,
            ip_address VARCHAR(45),
            user_agent_hash VARCHAR(64),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ NULL,
            UNIQUE (user_id, device_fingerprint_hash)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_trusted_devices_user ON trusted_devices (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_trusted_devices_expires ON trusted_devices (expires_at)")


def downgrade() -> None:
    op.drop_table("trusted_devices")
    op.drop_table("login_attempts")
    for column in [
        "locked_until",
        "last_failed_login_at",
        "failed_login_count",
        "last_login_country",
        "last_login_user_agent_hash",
        "last_login_ip",
        "last_login_at",
        "mfa_enrolled_at",
        "mfa_pending_secret_encrypted",
        "mfa_secret_encrypted",
        "mfa_enabled",
    ]:
        op.drop_column("users", column)
