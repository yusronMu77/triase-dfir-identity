"""Konteks bersama domain identity: pengaturan, basis data, kunci, kata sandi, jam, dan sink audit."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import timedelta

from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_common.hmac_auth import NonceCache
from sqlalchemy.ext.asyncio import AsyncEngine

from astria_identity.clock import Clock
from astria_identity.events import AuditSink
from astria_identity.keys import KeyStore
from astria_identity.passwords import Passwords
from astria_identity.settings import Settings


def sha256_bytes(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_user_id() -> str:
    """`usr_` + 12 karakter base32 acak (huruf besar dan 2-7), cocok dengan pola kontrak."""
    import base64

    return "usr_" + base64.b32encode(secrets.token_bytes(8)).decode()[:12]


def new_session_id() -> str:
    import base64

    return "ses_" + base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")


@dataclass
class Identity:
    settings: Settings
    db: Database
    keys: KeyStore
    passwords: Passwords
    audit: AuditSink
    clock: Clock = field(default_factory=Clock)
    nonces: NonceCache = field(default_factory=NonceCache)
    bootstrapped: bool = False
    schema_ready: asyncio.Event = field(default_factory=asyncio.Event)
    """Diset oleh `Migrations` setelah skema sesuai baseline (atau setelah stamp); bootstrap menunggunya."""

    @property
    def engine(self) -> AsyncEngine:
        if not self.db.is_ready:
            raise AstriaError("PENYIMPANAN_TIDAK_TERSEDIA", "basis data identity belum siap", 503)
        return self.db.engine

    @property
    def reauth_window(self) -> timedelta:
        return timedelta(minutes=self.settings.reauth_window_minutes)

    @property
    def overlap(self) -> timedelta:
        return timedelta(hours=self.settings.key_overlap_hours)

    def allowed_audiences(self, service: str) -> list[str]:
        table = self.settings.allowed_aud
        return table.get(service, table["_default"])

    def audience_allowed(self, service: str, audience: str) -> bool:
        allowed = self.allowed_audiences(service)
        return "*" in allowed or audience.removeprefix("svc:") in allowed
