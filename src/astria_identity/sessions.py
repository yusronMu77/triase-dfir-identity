"""Sesi browser: login, logout, re-autentikasi, introspeksi. Token opak (32 byte acak); hanya SHA-256 disimpan."""

from __future__ import annotations

import base64
import secrets
import time
from datetime import datetime, timedelta
from typing import Any

from astria_common.errors import AstriaError
from astria_common.log import get_logger
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity import events, metrics, throttle, users
from astria_identity.core import Identity, new_session_id, sha256_bytes
from astria_identity.tables import sessions
from astria_identity.tables import users as users_t

log = get_logger(__name__)
LAST_SEEN_INTERVAL = timedelta(seconds=60)


def invalid_credentials() -> AstriaError:
    return AstriaError("KREDENSIAL_TIDAK_VALID", "kredensial tidak valid", 401)


def new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def _user_hash(username: str) -> str:
    return users.username_hash(username)


def _login_limits(ident: Identity, username_hash: str, ip_hash: str) -> list[throttle.Limit]:
    limits = [throttle.Limit("username_hash", username_hash, ident.settings.login_fail_limit_user)]
    if ip_hash != throttle.NO_IP:
        limits.append(throttle.Limit("ip_hash", ip_hash, ident.settings.login_fail_limit_ip))
    return limits


async def _record_failure(
    ident: Identity,
    *,
    username_hash: str,
    ip_hash: str,
    reason: str,
    now: datetime,
    action: str = "identity.login.failed",
    actor: str | None = None,
) -> None:
    async with ident.engine.begin() as conn:
        await throttle.record(conn, username_hash=username_hash, ip_hash=ip_hash, success=False, now=now)
        await events.enqueue_audit(
            conn,
            events.audit_record(
                action=action,
                key=f"{action.replace('.', '-')}-{events.new_request_id()}",
                actor=actor or events.SERVICE_ACTOR,
                target_type="login",
                target_id=username_hash.removeprefix("u:"),
                payload={"username_hash": username_hash.removeprefix("u:"), "ip_hash": ip_hash, "reason": reason},
                occurred_at=now,
            ),
        )


async def login(
    ident: Identity, *, username: str, password: str, ip_hash: str | None, ua_hash: str | None
) -> dict[str, Any]:
    del ua_hash  # diterima agar kontrak lengkap; tidak disimpan
    now = ident.clock.now()
    uhash = _user_hash(username)
    iphash = ip_hash or throttle.NO_IP
    window = timedelta(minutes=ident.settings.login_fail_window_minutes)
    async with ident.engine.connect() as conn:
        try:
            await throttle.check(conn, _login_limits(ident, uhash, iphash), window=window, now=now)
        except throttle.Throttled:
            metrics.LOGIN_TOTAL.labels("throttled").inc()
            raise
        row = (await conn.execute(select(users_t).where(users_t.c.username_lower == username.lower()))).first()

    active = row is not None and row.status == "aktif"
    started = time.perf_counter()
    ok = await ident.passwords.verify(row.password_hash if active else None, password)
    metrics.LOGIN_DURATION.observe(time.perf_counter() - started)
    if not ok:
        inactive = row is not None and not active
        metrics.LOGIN_TOTAL.labels("nonaktif" if inactive else "salah").inc()
        await _record_failure(
            ident,
            username_hash=uhash,
            ip_hash=iphash,
            reason="akun_nonaktif" if inactive else "kredensial_salah",
            now=now,
        )
        log.info("login_gagal", username_hash=uhash.removeprefix("u:")[:16])
        raise invalid_credentials()

    token = new_token()
    session_id = new_session_id()
    idle = now + timedelta(minutes=ident.settings.session_idle_minutes)
    absolute = now + timedelta(hours=ident.settings.session_max_hours)
    rehash = await ident.passwords.hash(password) if ident.passwords.needs_rehash(row.password_hash) else None
    async with ident.engine.begin() as conn:
        await conn.execute(
            insert(sessions).values(
                session_id=session_id,
                user_id=row.user_id,
                token_hash=sha256_bytes(token),
                created_at=now,
                last_seen_at=now,
                idle_expires_at=idle,
                abs_expires_at=absolute,
            )
        )
        await throttle.record(conn, username_hash=uhash, ip_hash=iphash, success=True, now=now)
        if rehash is not None:
            await conn.execute(update(users_t).where(users_t.c.user_id == row.user_id).values(password_hash=rehash))
        roles = (await users.roles_of(conn, [row.user_id]))[row.user_id]
        await events.enqueue_audit(
            conn,
            events.audit_record(
                action="identity.login.succeeded",
                key=f"identity-login-succeeded-{session_id}",
                actor=row.user_id,
                target_type="session",
                target_id=session_id,
                payload={"user_id": row.user_id, "session_id": session_id, "ip_hash": iphash},
                occurred_at=now,
            ),
        )
    metrics.LOGIN_TOTAL.labels("sukses").inc()
    log.info("login_sukses", user_id=row.user_id, session_id=session_id)
    return {
        "session_token": token,
        "expires_at": absolute,
        "idle_expires_at": idle,
        "user": {"user_id": row.user_id, "username": row.username, "roles": roles},
    }


async def _active_session(conn: AsyncConnection, token: str, now: datetime) -> Any | None:
    """Baris sesi + status akun bila sesi masih berlaku, selain itu None."""
    row = (
        await conn.execute(
            select(sessions, users_t.c.status, users_t.c.username)
            .join(users_t, users_t.c.user_id == sessions.c.user_id)
            .where(sessions.c.token_hash == sha256_bytes(token))
        )
    ).first()
    if row is None or row.revoked_at is not None or row.status != "aktif":
        return None
    if row.idle_expires_at <= now or row.abs_expires_at <= now:
        return None
    return row


async def introspect(ident: Identity, token: str) -> dict[str, Any]:
    now = ident.clock.now()
    async with ident.engine.begin() as conn:
        row = await _active_session(conn, token, now)
        if row is None:
            metrics.INTROSPECT_TOTAL.labels("tidak_aktif").inc()
            return {"active": False}
        if now - row.last_seen_at > LAST_SEEN_INTERVAL:
            idle = now + timedelta(minutes=ident.settings.session_idle_minutes)
            await conn.execute(
                update(sessions)
                .where(sessions.c.session_id == row.session_id)
                .values(last_seen_at=now, idle_expires_at=idle)
            )
        roles = (await users.roles_of(conn, [row.user_id]))[row.user_id]  # peran dibaca langsung, tanpa cache
    metrics.INTROSPECT_TOTAL.labels("aktif").inc()
    return {
        "active": True,
        "user_id": row.user_id,
        "roles": roles,
        "reauth_at": row.reauth_at,
        "session_id": row.session_id,
    }


async def logout(ident: Identity, token: str) -> None:
    now = ident.clock.now()
    async with ident.engine.begin() as conn:
        row = await _active_session(conn, token, now)
        if row is None:
            raise invalid_credentials()
        await conn.execute(update(sessions).where(sessions.c.session_id == row.session_id).values(revoked_at=now))
        await events.enqueue_audit(
            conn,
            events.audit_record(
                action="identity.logout",
                key=f"identity-logout-{row.session_id}",
                actor=row.user_id,
                target_type="session",
                target_id=row.session_id,
                payload={"user_id": row.user_id, "session_id": row.session_id},
                occurred_at=now,
            ),
        )


async def reauth(ident: Identity, token: str, password: str) -> dict[str, Any]:
    now = ident.clock.now()
    window = timedelta(minutes=ident.settings.login_fail_window_minutes)
    async with ident.engine.connect() as conn:
        row = await _active_session(conn, token, now)
        if row is None:
            raise invalid_credentials()
        uhash = _user_hash(row.username)
        await throttle.check(
            conn, [throttle.Limit("username_hash", uhash, ident.settings.login_fail_limit_user)], window=window, now=now
        )
        stored = (
            await conn.execute(select(users_t.c.password_hash).where(users_t.c.user_id == row.user_id))
        ).scalar_one()
    if not await ident.passwords.verify(stored, password):
        await _record_failure(
            ident,
            username_hash=uhash,
            ip_hash=throttle.NO_IP,
            reason="reauth_gagal",
            now=now,
            action="identity.reauth.failed",
            actor=row.user_id,
        )
        raise invalid_credentials()
    async with ident.engine.begin() as conn:
        result = await conn.execute(
            update(sessions)
            .where(sessions.c.session_id == row.session_id, sessions.c.revoked_at.is_(None))
            .values(reauth_at=now)
        )
        if result.rowcount != 1:
            raise invalid_credentials()
        await events.enqueue_audit(
            conn,
            events.audit_record(
                action="identity.reauth",
                key=f"identity-reauth-{row.session_id}-{int(now.timestamp() * 1e6)}",
                actor=row.user_id,
                target_type="session",
                target_id=row.session_id,
                payload={"user_id": row.user_id, "session_id": row.session_id},
                occurred_at=now,
            ),
        )
    return {"reauth_at": now}


async def count_active(conn: AsyncConnection, now: datetime) -> int:
    from sqlalchemy import func

    return (
        await conn.execute(
            select(func.count())
            .select_from(sessions)
            .where(sessions.c.revoked_at.is_(None), sessions.c.idle_expires_at > now, sessions.c.abs_expires_at > now)
        )
    ).scalar_one()


async def purge(conn: AsyncConnection, *, older_than: datetime) -> int:
    """Hapus sesi yang sudah dicabut atau kedaluwarsa lebih dari 30 hari."""
    from sqlalchemy import or_

    result = await conn.execute(
        delete(sessions).where(
            or_(
                sessions.c.revoked_at < older_than,
                sessions.c.abs_expires_at < older_than,
                sessions.c.idle_expires_at < older_than,
            )
        )
    )
    return result.rowcount
