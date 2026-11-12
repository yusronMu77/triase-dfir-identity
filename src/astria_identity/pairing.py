"""Kode pairing kanal chat: 8 karakter Crockford base32 (40 bit), TTL 10 menit, sekali pakai, hanya hash disimpan."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

from astria_common.auth import ServicePrincipal
from astria_common.errors import AstriaError
from astria_common.log import get_logger
from sqlalchemy import delete, insert, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity import events, metrics, throttle
from astria_identity.core import Identity, sha256_bytes
from astria_identity.tables import pairing_codes
from astria_identity.tables import users as users_t

log = get_logger(__name__)
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32 tanpa I, L, O, U
CODE_LENGTH = 8
_CROCKFORD_FIX = str.maketrans({"I": "1", "L": "1", "O": "0"})


def generate_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))


def normalize(code: str) -> str:
    """Huruf besar, tanpa spasi atau tanda hubung; I/L dibaca 1 dan O dibaca 0 (aturan Crockford)."""
    return "".join(ch for ch in code.upper() if not ch.isspace() and ch != "-").translate(_CROCKFORD_FIX)


def hash_code(code: str) -> bytes:
    return sha256_bytes(normalize(code))


async def issue(ident: Identity, principal: ServicePrincipal, channel: str | None) -> dict[str, Any]:
    act = principal.act
    if not act or not isinstance(act.get("sub"), str):
        raise AstriaError(
            "PERAN_TIDAK_CUKUP", "kode pairing diterbitkan untuk pengguna yang sedang login (klaim act)", 403
        )
    user_id: str = act["sub"]
    now = ident.clock.now()
    expires = now + timedelta(minutes=ident.settings.pairing_ttl_minutes)
    async with ident.engine.begin() as conn:
        row = (await conn.execute(select(users_t.c.status).where(users_t.c.user_id == user_id))).first()
        if row is None or row.status != "aktif":
            raise AstriaError("PERAN_TIDAK_CUKUP", "akun tidak aktif", 403)
        code = generate_code()
        try:
            await conn.execute(
                insert(pairing_codes).values(
                    code_hash=hash_code(code), user_id=user_id, channel=channel, created_at=now, expires_at=expires
                )
            )
        except IntegrityError:  # tabrakan hash: peluang sekitar 2^-40 per kode aktif; pengguna cukup mencoba lagi
            raise AstriaError("PENYIMPANAN_TIDAK_TERSEDIA", "gagal menerbitkan kode, coba lagi", 503) from None
        await events.enqueue_audit(
            conn,
            events.audit_record(
                action="identity.pairing.issued",
                key=f"identity-pairing-issued-{events.new_request_id()}",
                actor=user_id,
                target_type="user",
                target_id=user_id,
                payload={"user_id": user_id, "channel": channel or "", "expires_at": expires.isoformat()},
                occurred_at=now,
            ),
        )
    metrics.PAIRING_TOTAL.labels("terbit").inc()
    log.info("pairing_terbit", user_id=user_id)
    return {"code": code, "channel": channel, "expires_at": expires}


async def claim(ident: Identity, *, channel: str, external_id_hash: str, code: str) -> dict[str, Any]:
    now = ident.clock.now()
    key = "p:" + external_id_hash
    window = timedelta(minutes=ident.settings.pairing_claim_window_minutes)
    limits = [throttle.Limit("username_hash", key, ident.settings.pairing_claim_limit)]
    async with ident.engine.connect() as conn:
        try:
            await throttle.check(conn, limits, window=window, now=now)
        except throttle.Throttled:
            metrics.PAIRING_TOTAL.labels("throttled").inc()
            raise

    code_hash = hash_code(code)
    failure: AstriaError | None = None
    result_label = ""
    async with ident.engine.begin() as conn:
        row = (
            await conn.execute(
                select(pairing_codes, users_t.c.status)
                .join(users_t, users_t.c.user_id == pairing_codes.c.user_id)
                .where(pairing_codes.c.code_hash == code_hash)
            )
        ).first()
        if row is None or row.status != "aktif" or (row.channel is not None and row.channel != channel):
            failure, result_label = AstriaError("KODE_TIDAK_VALID", "kode pairing tidak valid", 401), "salah"
        elif row.used_at is not None:
            failure, result_label = AstriaError("KODE_SUDAH_DIPAKAI", "kode pairing sudah dipakai", 409), "terpakai"
        elif row.expires_at <= now:
            failure, result_label = AstriaError("KODE_KEDALUWARSA", "kode pairing kedaluwarsa", 410), "kedaluwarsa"
        else:
            # Atomik: hanya satu dari dua klaim bersamaan yang mengubah satu baris.
            claimed = await conn.execute(
                update(pairing_codes)
                .where(
                    pairing_codes.c.code_hash == code_hash,
                    pairing_codes.c.used_at.is_(None),
                    pairing_codes.c.expires_at > now,
                )
                .values(used_at=now)
            )
            if claimed.rowcount != 1:
                failure, result_label = AstriaError("KODE_SUDAH_DIPAKAI", "kode pairing sudah dipakai", 409), "terpakai"
            else:
                await events.enqueue_audit(
                    conn,
                    events.audit_record(
                        action="identity.pairing.claimed",
                        key=f"identity-pairing-claimed-{code_hash.hex()}",
                        actor=row.user_id,
                        target_type="user",
                        target_id=row.user_id,
                        payload={"user_id": row.user_id, "channel": channel, "external_id_hash": external_id_hash},
                        occurred_at=now,
                        via="bot",
                    ),
                )
                metrics.PAIRING_TOTAL.labels("sukses").inc()
                log.info("pairing_terklaim", user_id=row.user_id, channel=channel)
                return {"user_id": row.user_id, "claimed_at": now}
    assert failure is not None
    metrics.PAIRING_TOTAL.labels(result_label).inc()
    async with ident.engine.begin() as conn:
        await throttle.record(conn, username_hash=key, ip_hash=throttle.NO_IP, success=False, now=now)
    raise failure


async def purge(conn: AsyncConnection, *, older_than: datetime) -> int:
    result = await conn.execute(
        delete(pairing_codes).where(or_(pairing_codes.c.used_at < older_than, pairing_codes.c.expires_at < older_than))
    )
    return result.rowcount
