"""Baseline: tabel identity (tables.py) dan outbox (astria-common).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-12

Ditulis tetap (tidak dibaca dari metadata), supaya perubahan tables.py di masa depan tidak mengubah baseline.
Sumber definisi: tables.py dan astria_common/outbox.py (common v0.2.3). DB yang dibuat lewat create_all
memakai definisi yang sama dan di-stamp ke revisi ini (lihat astria_identity.migrate).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UTC_DATETIME = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("role_code", sa.Text(), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("user_id", sa.Text(), primary_key=True),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("username_lower", sa.Text(), nullable=False, unique=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("created_at", UTC_DATETIME, nullable=False),
        sa.Column("updated_at", UTC_DATETIME, nullable=False),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Text(), sa.ForeignKey("users.user_id"), primary_key=True),
        sa.Column("role_code", sa.Text(), sa.ForeignKey("roles.role_code"), primary_key=True),
        sa.Column("granted_by", sa.Text(), nullable=False),
        sa.Column("granted_at", UTC_DATETIME, nullable=False),
    )
    op.create_table(
        "sessions",
        sa.Column("session_id", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column("created_at", UTC_DATETIME, nullable=False),
        sa.Column("last_seen_at", UTC_DATETIME, nullable=False),
        sa.Column("idle_expires_at", UTC_DATETIME, nullable=False),
        sa.Column("abs_expires_at", UTC_DATETIME, nullable=False),
        sa.Column("reauth_at", UTC_DATETIME, nullable=True),
        sa.Column("revoked_at", UTC_DATETIME, nullable=True),
    )
    op.create_index("sessions_user", "sessions", ["user_id", "revoked_at"])
    op.create_table(
        "pairing_codes",
        sa.Column("code_hash", sa.LargeBinary(), primary_key=True),
        sa.Column("user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("channel", sa.Text(), nullable=True),
        sa.Column("created_at", UTC_DATETIME, nullable=False),
        sa.Column("expires_at", UTC_DATETIME, nullable=False),
        sa.Column("used_at", UTC_DATETIME, nullable=True),
    )
    op.create_index("pairing_expires", "pairing_codes", ["expires_at"])
    op.create_table(
        "login_attempts",
        sa.Column("attempt_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username_hash", sa.Text(), nullable=False),
        sa.Column("ip_hash", sa.Text(), nullable=False),
        sa.Column("ts", UTC_DATETIME, nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
    )
    op.create_index("login_attempts_user", "login_attempts", ["username_hash", "ts"])
    op.create_index("login_attempts_ip", "login_attempts", ["ip_hash", "ts"])
    op.create_table(
        "service_keys",
        sa.Column("key_id", sa.Text(), primary_key=True),
        sa.Column("service", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("secret_enc", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", UTC_DATETIME, nullable=False),
        sa.Column("not_after", UTC_DATETIME, nullable=True),
    )
    op.create_index("service_keys_service", "service_keys", ["service", "status"])
    op.create_table(
        "signing_keys",
        sa.Column("kid", sa.Text(), primary_key=True),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("not_before", UTC_DATETIME, nullable=False),
        sa.Column("not_after", UTC_DATETIME, nullable=True),
    )
    # Tabel outbox dan processed_events milik astria-common (definisi sama dengan common v0.2.3).
    op.create_table(
        "outbox",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", UTC_DATETIME, nullable=False, server_default=sa.func.now()),
        sa.Column("published_at", UTC_DATETIME, nullable=True),
    )
    op.create_index(
        "outbox_belum_terbit",
        "outbox",
        ["created_at"],
        postgresql_where=sa.text("published_at IS NULL"),
    )
    op.create_table(
        "processed_events",
        sa.Column("consumer", sa.Text(), primary_key=True),
        sa.Column("event_id", sa.Text(), primary_key=True),
        sa.Column("processed_at", UTC_DATETIME, nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("processed_events")
    op.drop_index("outbox_belum_terbit", table_name="outbox")
    op.drop_table("outbox")
    op.drop_table("signing_keys")
    op.drop_index("service_keys_service", table_name="service_keys")
    op.drop_table("service_keys")
    op.drop_index("login_attempts_ip", table_name="login_attempts")
    op.drop_index("login_attempts_user", table_name="login_attempts")
    op.drop_table("login_attempts")
    op.drop_index("pairing_expires", table_name="pairing_codes")
    op.drop_table("pairing_codes")
    op.drop_index("sessions_user", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("user_roles")
    op.drop_table("users")
    op.drop_table("roles")
