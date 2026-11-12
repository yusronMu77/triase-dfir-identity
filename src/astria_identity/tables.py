"""Skema identity (SQLAlchemy Core). Berjalan di PostgreSQL dan SQLite; tidak ada fitur khusus satu dialek."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    TypeDecorator,
)

ROLES = ("analis", "dfir", "pimpinan", "admin")
ROLE_DESCRIPTIONS = {
    "analis": "Antrean, detail kartu, bukti, umpan balik, digest, serah terima",
    "dfir": "Seperti analis, ditambah kasus DFIR dan laporan",
    "pimpinan": "Hanya baca digest",
    "admin": "Akun, peran, konfigurasi, rahasia, audit, metrik",
}


class UTCDateTime(TypeDecorator[datetime]):
    """Waktu selalu UTC dan berzona waktu di Python; SQLite tidak menyimpan zona sehingga disamakan di sini."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("waktu tanpa zona tidak diizinkan")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_id", Text, primary_key=True),
    Column("username", Text, nullable=False),
    Column("username_lower", Text, nullable=False, unique=True),
    Column("display_name", Text, nullable=False),
    Column("status", Text, nullable=False),  # aktif | nonaktif
    Column("password_hash", Text, nullable=False),
    Column("created_at", UTCDateTime, nullable=False),
    Column("updated_at", UTCDateTime, nullable=False),
)

roles = Table(
    "roles",
    metadata,
    Column("role_code", Text, primary_key=True),
    Column("description", Text, nullable=False),
)

user_roles = Table(
    "user_roles",
    metadata,
    Column("user_id", Text, ForeignKey("users.user_id"), primary_key=True),
    Column("role_code", Text, ForeignKey("roles.role_code"), primary_key=True),
    Column("granted_by", Text, nullable=False),
    Column("granted_at", UTCDateTime, nullable=False),
)

sessions = Table(
    "sessions",
    metadata,
    Column("session_id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("users.user_id"), nullable=False),
    Column("token_hash", LargeBinary, nullable=False, unique=True),
    Column("created_at", UTCDateTime, nullable=False),
    Column("last_seen_at", UTCDateTime, nullable=False),
    Column("idle_expires_at", UTCDateTime, nullable=False),
    Column("abs_expires_at", UTCDateTime, nullable=False),
    Column("reauth_at", UTCDateTime, nullable=True),
    Column("revoked_at", UTCDateTime, nullable=True),
)
Index("sessions_user", sessions.c.user_id, sessions.c.revoked_at)

pairing_codes = Table(
    "pairing_codes",
    metadata,
    Column("code_hash", LargeBinary, primary_key=True),
    Column("user_id", Text, ForeignKey("users.user_id"), nullable=False),
    Column("channel", Text, nullable=True),
    Column("created_at", UTCDateTime, nullable=False),
    Column("expires_at", UTCDateTime, nullable=False),
    Column("used_at", UTCDateTime, nullable=True),
)
Index("pairing_expires", pairing_codes.c.expires_at)

login_attempts = Table(
    "login_attempts",
    metadata,
    # username_hash memuat ruang nama: `u:<sha256>` login/reauth per akun, `p:<sha256>` klaim pairing per kanal.
    Column("attempt_id", Integer, primary_key=True, autoincrement=True),
    Column("username_hash", Text, nullable=False),
    Column("ip_hash", Text, nullable=False),
    Column("ts", UTCDateTime, nullable=False),
    Column("success", Boolean, nullable=False),
)
Index("login_attempts_user", login_attempts.c.username_hash, login_attempts.c.ts)
Index("login_attempts_ip", login_attempts.c.ip_hash, login_attempts.c.ts)

service_keys = Table(
    "service_keys",
    metadata,
    Column("key_id", Text, primary_key=True),
    Column("service", Text, nullable=False),
    Column("status", Text, nullable=False),  # aktif | overlap | pensiun
    Column("secret_enc", LargeBinary, nullable=False),  # nonce(12) || ciphertext AES-256-GCM
    Column("created_at", UTCDateTime, nullable=False),
    Column("not_after", UTCDateTime, nullable=True),
)
Index("service_keys_service", service_keys.c.service, service_keys.c.status)

signing_keys = Table(
    "signing_keys",
    metadata,
    Column("kid", Text, primary_key=True),
    Column("public_key", LargeBinary, nullable=False),  # 32 byte; kunci privat tidak di basis data
    Column("status", Text, nullable=False),  # aktif | overlap | pensiun
    Column("not_before", UTCDateTime, nullable=False),
    Column("not_after", UTCDateTime, nullable=True),
)
