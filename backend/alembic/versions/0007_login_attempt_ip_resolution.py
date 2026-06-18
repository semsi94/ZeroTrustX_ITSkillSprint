"""login attempt ip resolution metadata

Revision ID: 0007_login_attempt_ip_resolution
Revises: 0006_mfa_challenges
Create Date: 2026-04-26 00:00:02.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0007_login_attempt_ip_resolution"
down_revision = "0006_mfa_challenges"
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
    _add_column_if_missing("login_attempts", sa.Column("direct_ip", sa.String(length=45), nullable=True))
    _add_column_if_missing("login_attempts", sa.Column("resolved_client_ip", sa.String(length=45), nullable=True))
    _add_column_if_missing("login_attempts", sa.Column("ip_resolution_source", sa.String(length=40), nullable=True))
    op.execute("""
        UPDATE login_attempts
        SET resolved_client_ip = COALESCE(resolved_client_ip, ip_address),
            direct_ip = COALESCE(direct_ip, ip_address),
            ip_resolution_source = COALESCE(ip_resolution_source, 'legacy')
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_login_attempts_resolved_client_ip ON login_attempts (resolved_client_ip)")


def downgrade() -> None:
    op.drop_column("login_attempts", "ip_resolution_source")
    op.drop_column("login_attempts", "resolved_client_ip")
    op.drop_column("login_attempts", "direct_ip")
