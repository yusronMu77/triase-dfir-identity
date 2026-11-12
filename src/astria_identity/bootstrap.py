"""Penyiapan saat start: peran, kunci penandatangan, kunci HMAC awal dari berkas, dan pengguna dev (bukan prod).

Berjalan di latar dengan percobaan ulang sampai basis data siap; /ready `down` sampai selesai.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from astria_common.component import Check
from astria_common.errors import AstriaError
from astria_common.log import get_logger
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity import passwords, users
from astria_identity.core import Identity
from astria_identity.keys import KeyStore, register_signing_key
from astria_identity.tables import ROLE_DESCRIPTIONS, ROLES, roles, service_keys
from astria_identity.tables import users as users_t
from astria_identity.tokens import key_aad, new_key_id

log = get_logger(__name__)
_SERVICE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


async def seed_roles(conn: AsyncConnection) -> None:
    present = {r.role_code for r in (await conn.execute(select(roles.c.role_code))).all()}
    missing = [r for r in ROLES if r not in present]
    if missing:
        await conn.execute(insert(roles), [{"role_code": r, "description": ROLE_DESCRIPTIONS[r]} for r in missing])


def load_service_keys_file(path: Path | None) -> dict[str, bytes]:
    if path is None or not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    keys: dict[str, bytes] = {}
    for name, value in raw.items():
        if not _SERVICE_NAME.match(name):
            raise ValueError(f"nama layanan tidak valid di berkas kunci: {name!r}")
        key = bytes.fromhex(value)
        if len(key) < 32:
            raise ValueError(f"kunci layanan {name} kurang dari 32 byte")
        keys[name] = key
    return keys


async def seed_service_keys(conn: AsyncConnection, keystore: KeyStore, seeds: dict[str, bytes], now: datetime) -> int:
    """Masukkan kunci dari berkas bila belum ada baris (aktif, overlap, atau pensiun) dengan nilai yang sama.

    Kunci yang sudah dirotasi tetap sah: nilai lama di berkas cocok dengan barisnya (overlap atau pensiun) sehingga
    tidak dimasukkan lagi sebagai kunci aktif."""
    added = 0
    for service, secret in seeds.items():
        rows = (await conn.execute(select(service_keys).where(service_keys.c.service == service))).all()
        known = False
        for row in rows:
            try:
                if keystore.decrypt_secret(bytes(row.secret_enc), aad=key_aad(service, row.key_id)) == secret:
                    known = True
                    break
            except Exception:  # noqa: BLE001, S112 - baris rusak atau kunci induk berbeda: tidak dihitung cocok
                continue
        if known:
            continue
        key_id = new_key_id()
        await conn.execute(
            insert(service_keys).values(
                key_id=key_id,
                service=service,
                status="aktif",
                secret_enc=keystore.encrypt_secret(secret, aad=key_aad(service, key_id)),
                created_at=now,
                not_after=None,
            )
        )
        added += 1
    return added


def load_seed_users(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("berkas pengguna seed harus berupa daftar")
    return raw


async def seed_users(ident: Identity, conn: AsyncConnection, items: list[dict[str, Any]]) -> int:
    """Pengguna dev; idempoten menurut username (yang sudah ada dilewati)."""
    added = 0
    for item in items:
        username = item["username"]
        exists = (
            await conn.execute(select(users_t.c.user_id).where(users_t.c.username_lower == username.lower()))
        ).first()
        if exists is not None:
            continue
        passwords.check_policy(item["password"], username)
        await users.create(
            ident,
            conn,
            username=username,
            display_name=item.get("display_name", username),
            password_hash=await ident.passwords.hash(item["password"]),
            role_list=users.validate_roles(list(item["roles"])),
            granted_by="seed",
            user_id=item.get("user_id"),
        )
        added += 1
    return added


@dataclass
class Bootstrap:
    """Komponen: menyiapkan data awal setelah basis data siap."""

    ident: Identity
    name: str = "bootstrap"
    required: bool = True
    error: str | None = None
    _task: asyncio.Task[None] | None = None
    _done: asyncio.Event | None = None

    async def start(self) -> None:
        self._done = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="identity-bootstrap")
        try:  # biasanya selesai seketika (SQLite, atau PostgreSQL yang sudah siap); jika tidak, lanjut di latar
            await asyncio.wait_for(asyncio.shield(self._done.wait()), timeout=5)
        except TimeoutError:
            log.warning("bootstrap_berlanjut_di_latar")

    async def _run(self) -> None:
        delay = 0.5
        while True:
            try:
                await self.ident.db.wait_ready()
                await self.ident.schema_ready.wait()
                await self._once()
                self.ident.bootstrapped = True
                self.error = None
                assert self._done is not None
                self._done.set()
                log.info("bootstrap_selesai")
                return
            except Exception as exc:  # noqa: BLE001 - dicoba ulang; status terlihat di /ready
                self.error = type(exc).__name__
                log.warning("bootstrap_gagal", error=self.error, retry_in=delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 10)

    async def _once(self) -> None:
        ident = self.ident
        now = ident.clock.now()
        async with ident.engine.begin() as conn:
            await seed_roles(conn)
            if ident.keys.signing is not None:
                await register_signing_key(conn, ident.keys.signing, now, ident.overlap)
            if ident.keys.master is not None:
                seeded = await seed_service_keys(
                    conn, ident.keys, load_service_keys_file(ident.settings.service_keys_file), now
                )
                if seeded:
                    log.info("kunci_layanan_disemai", count=seeded)
        items = load_seed_users(ident.settings.seed_users_file)
        if items:
            if ident.settings.env == "prod":
                raise AstriaError("SEED_DILARANG", "seed pengguna dilarang di produksi", 500)
            async with ident.engine.begin() as conn:
                count = await seed_users(ident, conn, items)
            log.info("pengguna_seed", added=count)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)  # selesai dulu sebelum DB ditutup

    async def check(self) -> Check:
        if self.ident.bootstrapped:
            return Check("ok")
        return Check("down", f"menyiapkan data awal ({self.error or 'menunggu basis data'})")
