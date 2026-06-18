"""mfa challenge replay protection

Revision ID: 0006_mfa_challenges
Revises: 0005_adaptive_mfa
Create Date: 2026-04-26 00:00:01.000000
"""

from alembic import op


revision = "0006_mfa_challenges"
down_revision = "0005_adaptive_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS mfa_challenges (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username VARCHAR(100) NOT NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_mfa_challenges_token_hash ON mfa_challenges (token_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_mfa_challenges_expires ON mfa_challenges (expires_at)")


def downgrade() -> None:
    op.drop_table("mfa_challenges")
