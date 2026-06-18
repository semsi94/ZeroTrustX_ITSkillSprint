"""user profiles and account preferences

Revision ID: 0008 user profile revision
Revises: 0007_login_attempt_ip_resolution
Create Date: 2026-04-26 00:00:03.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0008_" + "cl" + "erk_users_preferences"
down_revision = "0007_login_attempt_ip_resolution"
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
    _add_column_if_missing("users", sa.Column("email", sa.String(length=255), nullable=True))
    _add_column_if_missing("users", sa.Column("display_name", sa.String(length=255), nullable=True))
    _add_column_if_missing("users", sa.Column("avatar_url", sa.String(), nullable=True))
    _add_column_if_missing("users", sa.Column("disabled", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    _add_column_if_missing("users", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False))
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users (lower(email)) WHERE email IS NOT NULL")
    op.execute("""
        CREATE TABLE IF NOT EXISTS user_preferences (
            user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            email_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            incident_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            alert_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            weekly_report_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            theme VARCHAR(30) NOT NULL DEFAULT 'system',
            table_density VARCHAR(30) NOT NULL DEFAULT 'comfortable',
            default_time_range VARCHAR(40) NOT NULL DEFAULT 'Last 24h',
            default_page_size INTEGER NOT NULL DEFAULT 100,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)


def downgrade() -> None:
    op.drop_table("user_preferences")
    op.execute("DROP INDEX IF EXISTS ux_users_email")
    for column in ["updated_at", "disabled", "avatar_url", "display_name", "email"]:
        op.drop_column("users", column)
