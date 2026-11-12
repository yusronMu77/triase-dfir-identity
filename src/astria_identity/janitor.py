"""Pekerjaan latar: muat ulang kunci penandatangan yang dirotasi, perbarui gauge, dan bersihkan data lama.

Putaran 30 detik: kunci dan gauge. Sekali per jam (dan sekali di awal): hapus sesi dan percobaan login lama
(30 hari), kode pairing terpakai atau kedaluwarsa (24 jam), dan pensiunkan kunci overlap yang lewat batas.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta

from astria_common.component import Check
from astria_common.log import get_logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity import metrics, pairing, sessions, throttle
from astria_identity.core import Identity
from astria_identity.keys import register_signing_key
from astria_identity.tables import service_keys, signing_keys

log = get_logger(__name__)
TICK_SECONDS = 30
CLEANUP_EVERY = timedelta(hours=1)
RETAIN = timedelta(days=30)
PAIRING_RETAIN = timedelta(hours=24)


async def retire_expired_keys(conn: AsyncConnection, now: datetime) -> int:
    total = 0
    for table in (service_keys, signing_keys):
        result = await conn.execute(
            update(table).where(table.c.status == "overlap", table.c.not_after <= now).values(status="pensiun")
        )
        total += result.rowcount
    return total


async def cleanup(ident: Identity) -> dict[str, int]:
    now = ident.clock.now()
    async with ident.engine.begin() as conn:
        return {
            "sesi": await sessions.purge(conn, older_than=now - RETAIN),
            "percobaan_login": await throttle.purge(conn, older_than=now - RETAIN),
            "pairing": await pairing.purge(conn, older_than=now - PAIRING_RETAIN),
            "kunci_pensiun": await retire_expired_keys(conn, now),
        }


async def refresh_gauges(ident: Identity) -> None:
    now = ident.clock.now()
    rotate_days = ident.settings.key_rotation_days
    async with ident.engine.connect() as conn:
        metrics.SESSIONS_ACTIVE.set(await sessions.count_active(conn, now))
        created = (
            (await conn.execute(select(service_keys.c.created_at).where(service_keys.c.status == "aktif")))
            .scalars()
            .all()
        )
        started = (
            (await conn.execute(select(signing_keys.c.not_before).where(signing_keys.c.status == "aktif")))
            .scalars()
            .all()
        )
    if created:
        metrics.KEY_DAYS.labels("service_hmac").set(rotate_days - (now - min(created)).total_seconds() / 86400)
    if started:
        metrics.KEY_DAYS.labels("signing").set(rotate_days - (now - min(started)).total_seconds() / 86400)


async def reload_signing_key(ident: Identity) -> None:
    key = ident.keys.reload_if_changed()
    if key is not None:
        async with ident.engine.begin() as conn:
            await register_signing_key(conn, key, ident.clock.now(), ident.overlap)


@dataclass
class Janitor:
    ident: Identity
    name: str = "janitor"
    required: bool = False
    _task: asyncio.Task[None] | None = None
    _last_cleanup: datetime | None = None
    error: str | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="identity-janitor")

    async def _run(self) -> None:
        await self.ident.db.wait_ready()
        while True:
            try:
                await self.tick()
                self.error = None
            except Exception as exc:  # noqa: BLE001 - putaran berikutnya mencoba lagi
                self.error = type(exc).__name__
                log.warning("janitor_gagal", error=self.error)
            await asyncio.sleep(TICK_SECONDS)

    async def tick(self) -> None:
        if not self.ident.bootstrapped:
            return
        await reload_signing_key(self.ident)
        await refresh_gauges(self.ident)
        now = self.ident.clock.now()
        if self._last_cleanup is None or now - self._last_cleanup >= CLEANUP_EVERY:
            removed = await cleanup(self.ident)
            self._last_cleanup = now
            log.info("pembersihan_selesai", **removed)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)  # selesai dulu sebelum DB ditutup

    async def check(self) -> Check:
        return Check("degraded", f"putaran terakhir gagal ({self.error})") if self.error else Check("ok")
