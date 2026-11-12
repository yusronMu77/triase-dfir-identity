"""Kunci identity: penandatanganan Ed25519 (berkas), kunci induk AES-GCM (berkas), dan registri kunci di basis data.

- Kunci privat penandatanganan dan kunci induk hanya ada di berkas (izin 0600), tidak di basis data, env, atau repo.
- `signing_keys` menyimpan kunci publik: aktif, overlap (24 jam default, masih dipublikasikan di JWKS), pensiun.
- `service_keys` menyimpan kunci HMAC layanan terenkripsi AES-256-GCM dengan kunci induk.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from astria_common.auth import SigningKey, load_or_create_signing_key
from astria_common.component import Check
from astria_common.log import get_logger
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity.settings import Settings
from astria_identity.tables import service_keys, signing_keys

log = get_logger(__name__)
NONCE_BYTES = 12


def load_or_create_master_key(path: Path) -> bytes:
    """Kunci induk 32 byte mentah. Dibuat sekali dengan izin 0600; hilangnya berarti kunci layanan tidak bisa dibuka."""
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError("kunci induk harus 32 byte")
        return key
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def encrypt(master: bytes, plain: bytes, *, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce + AESGCM(master).encrypt(nonce, plain, aad)


def decrypt(master: bytes, blob: bytes, *, aad: bytes) -> bytes:
    return AESGCM(master).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)


def public_raw(key: SigningKey) -> bytes:
    return key.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def jwk_from_public(kid: str, raw: bytes) -> dict[str, str]:
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig"}


def write_new_signing_key(path: Path) -> SigningKey:
    """Tulis kunci baru secara atomik (berkas sementara 0600 lalu rename) dan kembalikan."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    os.replace(tmp, path)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return SigningKey(kid="idn-" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()[:12], private_key=key)


async def register_signing_key(conn: AsyncConnection, key: SigningKey, now: datetime, overlap: timedelta) -> bool:
    """Catat kunci aktif di `signing_keys`; kunci aktif lain menjadi overlap. True bila ada perubahan."""
    changed = False
    row = (await conn.execute(select(signing_keys.c.status).where(signing_keys.c.kid == key.kid))).first()
    if row is None:
        await conn.execute(
            insert(signing_keys).values(
                kid=key.kid, public_key=public_raw(key), status="aktif", not_before=now, not_after=None
            )
        )
        changed = True
    elif row.status != "aktif":
        await conn.execute(
            update(signing_keys).where(signing_keys.c.kid == key.kid).values(status="aktif", not_after=None)
        )
        changed = True
    demoted = await conn.execute(
        update(signing_keys)
        .where(signing_keys.c.status == "aktif", signing_keys.c.kid != key.kid)
        .values(status="overlap", not_after=now + overlap)
    )
    return changed or demoted.rowcount > 0


@dataclass
class KeyStore:
    """Komponen: memuat kunci dari berkas saat start. /ready `down` bila kunci penandatangan atau induk tidak ada."""

    settings: Settings
    name: str = "keys"
    required: bool = True
    signing: SigningKey | None = None
    master: bytes | None = None
    error: str | None = None
    _signing_mtime: float = 0.0

    async def start(self) -> None:
        try:
            self.master = load_or_create_master_key(self.settings.master_key_file)
            self.signing = load_or_create_signing_key(self.settings.signing_key_path)
            self._signing_mtime = self.settings.signing_key_path.stat().st_mtime
            log.info("kunci_dimuat", kid=self.signing.kid)
        except (OSError, ValueError) as exc:
            self.error = type(exc).__name__
            log.error("kunci_gagal_dimuat", error=self.error)

    async def stop(self) -> None:
        return None

    def reload_if_changed(self) -> SigningKey | None:
        """Muat ulang kunci penandatangan bila berkasnya diganti (rotasi lewat CLI); kembalikan kunci baru atau None."""
        try:
            mtime = self.settings.signing_key_path.stat().st_mtime
        except OSError:
            return None
        if mtime == self._signing_mtime:
            return None
        try:
            key = load_or_create_signing_key(self.settings.signing_key_path)
        except OSError, ValueError:
            log.error("kunci_baru_gagal_dimuat")
            return None
        self._signing_mtime = mtime
        if self.signing is not None and key.kid == self.signing.kid:
            return None
        self.signing = key
        log.info("kunci_penandatangan_berganti", kid=key.kid)
        return key

    def encrypt_secret(self, plain: bytes, *, aad: bytes) -> bytes:
        if self.master is None:
            raise RuntimeError("kunci induk tidak termuat")
        return encrypt(self.master, plain, aad=aad)

    def decrypt_secret(self, blob: bytes, *, aad: bytes) -> bytes:
        if self.master is None:
            raise RuntimeError("kunci induk tidak termuat")
        return decrypt(self.master, blob, aad=aad)

    async def check(self) -> Check:
        if self.master is None:
            return Check("down", f"kunci induk tidak tersedia ({self.error})")
        if self.signing is None:
            return Check("down", f"kunci penandatangan tidak tersedia ({self.error})")
        return Check("ok", f"kid={self.signing.kid}")


async def service_key_rows(conn: AsyncConnection, service: str, now: datetime) -> list[Any]:
    """Kunci HMAC yang masih berlaku (aktif, atau overlap yang belum lewat batas) untuk satu layanan."""
    rows = (
        await conn.execute(
            select(service_keys).where(
                service_keys.c.service == service, service_keys.c.status.in_(("aktif", "overlap"))
            )
        )
    ).all()
    return [r for r in rows if r.not_after is None or r.not_after > now]
