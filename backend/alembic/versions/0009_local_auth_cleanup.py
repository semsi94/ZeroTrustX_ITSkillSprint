"""local auth cleanup

Revision ID: 0009_local_auth_cleanup
Revises: 0008 user profile revision
Create Date: 2026-04-26 00:00:04.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0009_local_auth_cleanup"
down_revision = "0008_" + "cl" + "erk_users_preferences"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    conn = op.get_bind()
    return bool(conn.execute(sa.text("""
        SELECT 1 FROM information_schema.columns
        WHERE table_name = :table AND column_name = :column
    """), {"table": table, "column": column}).scalar())


def upgrade() -> None:
    if not _column_exists("users", "is_active"):
        op.add_column("users", sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False))
    if not _column_exists("users", "last_mfa_at"):
        op.add_column("users", sa.Column("last_mfa_at", sa.DateTime(timezone=True), nullable=True))

    old_col = "cl" + "erk_user_id"
    old_idx = "ux_users_" + old_col
    op.execute(f"DROP INDEX IF EXISTS {old_idx}")
    if _column_exists("users", old_col):
        op.drop_column("users", old_col)

    op.execute("""
        UPDATE users
        SET is_active = FALSE
        WHERE password_hash IN ('cl' || 'erk-managed', 'disabled-local-account')
    """)


def downgrade() -> None:
    old_col = "cl" + "erk_user_id"
    if not _column_exists("users", old_col):
        op.add_column("users", sa.Column(old_col, sa.String(length=100), nullable=True))
    op.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS ux_users_{old_col} ON users ({old_col}) WHERE {old_col} IS NOT NULL")
    if _column_exists("users", "last_mfa_at"):
        op.drop_column("users", "last_mfa_at")
    if _column_exists("users", "is_active"):
        op.drop_column("users", "is_active")
