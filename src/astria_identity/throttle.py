"""Throttle berbasis tabel `login_attempts`: hitung kegagalan dalam jendela waktu, per akun, IP, atau identitas kanal.

Pencatatan kegagalan dilakukan di transaksi sendiri (commit) sebelum galat dilempar, sehingga tetap tercatat.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil

from astria_common.errors import AstriaError
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity.tables import login_attempts

NO_IP = "-"


class Throttled(AstriaError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("TERLALU_BANYAK_PERCOBAAN", "terlalu banyak percobaan, coba lagi nanti", 429)
        self.retry_after = max(retry_after, 1)


@dataclass(frozen=True)
class Limit:
    column: str  # "username_hash" atau "ip_hash"
    key: str
    limit: int


async def check(conn: AsyncConnection, limits: list[Limit], *, window: timedelta, now: datetime) -> None:
    """Lempar `Throttled` bila salah satu batas kegagalan terlampaui dalam jendela."""
    since = now - window
    worst = 0
    for lim in limits:
        col = getattr(login_attempts.c, lim.column)
        rows = (
            await conn.execute(
                select(login_attempts.c.ts)
                .where(col == lim.key, login_attempts.c.success.is_(False), login_attempts.c.ts > since)
                .order_by(login_attempts.c.ts.desc())
                .limit(lim.limit)
            )
        ).all()
        if len(rows) >= lim.limit:
            # Batas terbuka lagi saat kegagalan ke-`limit` (dihitung dari yang terbaru) keluar dari jendela.
            oldest_counted = rows[-1].ts
            worst = max(worst, ceil((oldest_counted + window - now).total_seconds()))
    if worst:
        raise Throttled(worst)


async def record(conn: AsyncConnection, *, username_hash: str, ip_hash: str, success: bool, now: datetime) -> None:
    await conn.execute(
        insert(login_attempts).values(username_hash=username_hash, ip_hash=ip_hash, ts=now, success=success)
    )


async def purge(conn: AsyncConnection, *, older_than: datetime) -> int:
    from sqlalchemy import delete

    result = await conn.execute(delete(login_attempts).where(login_attempts.c.ts < older_than))
    return result.rowcount


async def count(conn: AsyncConnection) -> int:
    return (await conn.execute(select(func.count()).select_from(login_attempts))).scalar_one()
