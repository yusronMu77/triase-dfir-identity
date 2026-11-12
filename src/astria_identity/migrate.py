"""Migrasi Alembic skema identity (dan tabel outbox milik astria-common) di PostgreSQL dan SQLite.

Aturan start (`migrate_sync`), berdasarkan tabel yang sudah ada di skema layanan:

- ada `alembic_version`: `upgrade head` (no-op bila sudah di head);
- skema kosong: `upgrade head` (membuat baseline);
- semua tabel sudah ada tapi belum ada riwayat (DB yang dibuat lewat `create_all` di Tahap 0 atau 4): `stamp head`
  tanpa DDL, data tidak disentuh;
- sebagian tabel saja: galat, tidak ada tebakan. Perbaiki manual atau kosongkan skema.

Migrasi di-embed di paket (`astria_identity/migrations`), jadi ikut wheel dan image.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from alembic import command
from alembic.config import Config
from astria_common import outbox
from astria_common.component import Check
from astria_common.db import Database
from astria_common.log import get_logger
from sqlalchemy import MetaData, inspect
from sqlalchemy.engine import Connection

from astria_identity import tables
from astria_identity.core import Identity
from astria_identity.settings import Settings

log = get_logger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
VERSION_TABLE = "alembic_version"

# Metadata target migrasi: tabel identity plus tabel outbox (dibuat `astria_common`, tetap bagian skema layanan).
TARGET_METADATA = MetaData()
for _table in (*tables.metadata.tables.values(), *outbox.metadata.tables.values()):
    _table.to_metadata(TARGET_METADATA)

MigrateAction = Literal["create", "upgrade", "stamp"]


class MigrationError(RuntimeError):
    """Skema tidak bisa dimigrasikan dengan aman; tidak ada perubahan yang dilakukan."""


def _config(conn: Connection, schema: str | None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    # env.py memakai koneksi yang sudah dibuka pemanggil (satu transaksi, tanpa event loop baru).
    cfg.attributes["connection"] = conn
    cfg.attributes["schema"] = schema
    return cfg


def migrate_sync(conn: Connection, schema: str | None, *, stamp_only: bool = False) -> MigrateAction:
    """Jalankan aturan start di dalam `conn` (sinkron; dipanggil lewat `AsyncConnection.run_sync`).

    `stamp_only=True` hanya menandai head untuk skema lengkap tanpa riwayat; skema kosong ditolak.
    """
    existing = set(inspect(conn).get_table_names(schema=schema))
    cfg = _config(conn, schema)
    if VERSION_TABLE in existing:
        command.upgrade(cfg, "head")
        return "upgrade"
    expected = {t.name for t in TARGET_METADATA.sorted_tables}
    if not existing & expected:
        if stamp_only:
            raise MigrationError("skema kosong; jalankan tanpa --stamp untuk membuat baseline")
        command.upgrade(cfg, "head")
        return "create"
    missing = sorted(expected - existing)
    if missing:
        raise MigrationError(f"skema sebagian tanpa riwayat migrasi; tabel hilang: {', '.join(missing)}")
    command.stamp(cfg, "head")
    return "stamp"


def schema_for(db: Database, settings: Settings) -> str | None:
    """SQLite tidak punya skema; PostgreSQL memakai `ASTRIA_DB_SCHEMA` bila diisi."""
    return settings.db_schema if db.dialect == "postgresql" else None


async def migrate_database(db: Database, settings: Settings, *, stamp_only: bool = False) -> MigrateAction:
    """Migrasi basis data yang sudah siap (`db.wait_ready()` harus sudah dipanggil)."""
    async with db.engine.begin() as conn:
        action = await conn.run_sync(migrate_sync, schema_for(db, settings), stamp_only=stamp_only)
    log.info("migrasi_selesai", action=action)
    return action


@dataclass
class Migrations:
    """Komponen: menjalankan migrasi setelah basis data siap, sebelum bootstrap. /ready `down` sampai selesai."""

    ident: Identity
    name: str = "migrations"
    required: bool = True
    error: str | None = None
    action: MigrateAction | None = None
    _task: asyncio.Task[None] | None = field(default=None, repr=False)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="identity-migrations")

    async def _run(self) -> None:
        delay = 0.5
        while True:
            try:
                await self.ident.db.wait_ready()
                self.action = await migrate_database(self.ident.db, self.ident.settings)
                self.error = None
                self.ident.schema_ready.set()
                return
            except Exception as exc:  # noqa: BLE001 - dicoba ulang; status terlihat di /ready
                self.error = type(exc).__name__
                log.warning("migrasi_gagal", error=self.error, retry_in=delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 10)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def check(self) -> Check:
        if self.ident.schema_ready.is_set():
            return Check("ok")
        return Check("down", f"memigrasi skema ({self.error or 'menunggu basis data'})")
