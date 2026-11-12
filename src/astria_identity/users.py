"""Akun dan peran: baca, buat, ubah, ganti peran; otorisasi admin untuk aksi sensitif."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from astria_common.auth import ServicePrincipal
from astria_common.errors import AstriaError
from astria_common.log import get_logger
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity import events, passwords
from astria_identity.core import Identity, new_user_id, sha256_hex
from astria_identity.tables import ROLES, sessions, user_roles, users

log = get_logger(__name__)


def not_found() -> AstriaError:
    return AstriaError("PENGGUNA_TIDAK_DITEMUKAN", "pengguna tidak ditemukan", 404)


async def roles_of(conn: AsyncConnection, user_ids: list[str]) -> dict[str, list[str]]:
    if not user_ids:
        return {}
    rows = (
        await conn.execute(
            select(user_roles.c.user_id, user_roles.c.role_code)
            .where(user_roles.c.user_id.in_(user_ids))
            .order_by(user_roles.c.role_code)
        )
    ).all()
    out: dict[str, list[str]] = {uid: [] for uid in user_ids}
    for row in rows:
        out[row.user_id].append(row.role_code)
    return out


def to_user(row: Any, roles: list[str]) -> dict[str, Any]:
    """Bentuk `User` pada kontrak."""
    return {
        "user_id": row.user_id,
        "username": row.username,
        "display_name": row.display_name,
        "active": row.status == "aktif",
        "roles": roles,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


async def get(conn: AsyncConnection, user_id: str) -> dict[str, Any]:
    row = (await conn.execute(select(users).where(users.c.user_id == user_id))).first()
    if row is None:
        raise not_found()
    return to_user(row, (await roles_of(conn, [user_id]))[user_id])


async def list_page(
    conn: AsyncConnection, *, limit: int, cursor: str | None
) -> tuple[list[dict[str, Any]], str | None]:
    query = select(users).order_by(users.c.user_id).limit(limit + 1)
    if cursor:
        query = query.where(users.c.user_id > cursor)
    rows = (await conn.execute(query)).all()
    page = rows[:limit]
    roles = await roles_of(conn, [r.user_id for r in page])
    items = [to_user(r, roles[r.user_id]) for r in page]
    return items, (page[-1].user_id if len(rows) > limit else None)


def validate_roles(role_list: list[str]) -> list[str]:
    unique = sorted(set(role_list))
    if not unique or any(r not in ROLES for r in unique):
        raise AstriaError("VALIDASI_GAGAL", "peran tidak dikenal atau kosong", 422)
    return unique


async def revoke_sessions(conn: AsyncConnection, user_id: str, now: datetime) -> int:
    result = await conn.execute(
        update(sessions).where(sessions.c.user_id == user_id, sessions.c.revoked_at.is_(None)).values(revoked_at=now)
    )
    return result.rowcount


async def create(
    ident: Identity,
    conn: AsyncConnection,
    *,
    username: str,
    display_name: str,
    password_hash: str,
    role_list: list[str],
    granted_by: str,
    user_id: str | None = None,
) -> dict[str, Any]:
    now = ident.clock.now()
    uid = user_id or new_user_id()
    taken = (await conn.execute(select(users.c.user_id).where(users.c.username_lower == username.lower()))).first()
    if taken is not None:
        raise AstriaError("USERNAME_SUDAH_ADA", "username sudah dipakai", 409)
    try:
        await conn.execute(
            insert(users).values(
                user_id=uid,
                username=username,
                username_lower=username.lower(),
                display_name=display_name,
                status="aktif",
                password_hash=password_hash,
                created_at=now,
                updated_at=now,
            )
        )
    except IntegrityError as exc:  # balapan dua pembuatan sekaligus; transaksi dibatalkan oleh pemanggil
        raise AstriaError("USERNAME_SUDAH_ADA", "username sudah dipakai", 409) from exc
    await conn.execute(
        insert(user_roles),
        [{"user_id": uid, "role_code": r, "granted_by": granted_by, "granted_at": now} for r in role_list],
    )
    return await get(conn, uid)


class AdminActor:
    def __init__(self, user_id: str, session_id: str | None) -> None:
        self.user_id = user_id
        self.session_id = session_id


async def authorize_admin(
    ident: Identity, conn: AsyncConnection, principal: ServicePrincipal, *, reauth: bool
) -> AdminActor:
    """Aksi admin: `act` wajib; peran `act.sub` dibaca ulang dari DB (klaim `act.roles` tidak dipercaya);
    untuk aksi sensitif sesi `act.session_id` harus aktif dan re-autentikasi masih dalam jendela."""
    act = principal.act
    if not act or not isinstance(act.get("sub"), str):
        raise AstriaError("PERAN_TIDAK_CUKUP", "aksi ini memerlukan pengguna admin (klaim act)", 403)
    user_id: str = act["sub"]
    row = (await conn.execute(select(users).where(users.c.user_id == user_id))).first()
    roles = (await roles_of(conn, [user_id])).get(user_id, []) if row is not None else []
    if row is None or row.status != "aktif" or "admin" not in roles:
        raise AstriaError("PERAN_TIDAK_CUKUP", "peran tidak cukup untuk aksi ini", 403)
    session_id = act.get("session_id") if isinstance(act.get("session_id"), str) else None
    if reauth:
        now = ident.clock.now()
        sess = None
        if session_id:
            sess = (
                await conn.execute(
                    select(sessions).where(sessions.c.session_id == session_id, sessions.c.user_id == user_id)
                )
            ).first()
        ok = (
            sess is not None
            and sess.revoked_at is None
            and sess.idle_expires_at > now
            and sess.abs_expires_at > now
            and sess.reauth_at is not None
            and now - sess.reauth_at <= ident.reauth_window
        )
        if not ok:
            raise AstriaError("REAUTH_DIPERLUKAN", "konfirmasi ulang kata sandi diperlukan untuk aksi ini", 403)
    return AdminActor(user_id, session_id)


async def count_admins(conn: AsyncConnection) -> int:
    rows = (
        await conn.execute(
            select(user_roles.c.user_id)
            .join(users, users.c.user_id == user_roles.c.user_id)
            .where(user_roles.c.role_code == "admin", users.c.status == "aktif")
        )
    ).all()
    return len(rows)


async def create_user(
    ident: Identity,
    principal: ServicePrincipal,
    *,
    username: str,
    display_name: str,
    password: str,
    role_list: list[str],
    request_id: str,
) -> dict[str, Any]:
    passwords.check_policy(password, username)
    role_list = validate_roles(role_list)
    password_hash = await ident.passwords.hash(password)
    async with ident.engine.begin() as conn:
        actor = await authorize_admin(ident, conn, principal, reauth=True)
        user = await create(
            ident,
            conn,
            username=username,
            display_name=display_name,
            password_hash=password_hash,
            role_list=role_list,
            granted_by=actor.user_id,
        )
        now = ident.clock.now()
        await ident.audit.record(
            events.audit_record(
                action="identity.user.created",
                key=f"identity-user-created-{request_id}",
                actor=actor.user_id,
                target_type="user",
                target_id=user["user_id"],
                payload={
                    "user_id": user["user_id"],
                    "username": username,
                    "roles": role_list,
                    "created_by": actor.user_id,
                },
                occurred_at=now,
            )
        )
    log.info("pengguna_dibuat", user_id=user["user_id"], by=actor.user_id)
    return user


async def update_user(
    ident: Identity,
    principal: ServicePrincipal,
    user_id: str,
    *,
    display_name: str | None,
    active: bool | None,
    password: str | None,
) -> dict[str, Any]:
    new_hash = None
    # Pemeriksaan awal di luar transaksi tulis agar argon2 (CPU) tidak berjalan sambil menahan kunci basis data.
    async with ident.engine.connect() as conn:
        await authorize_admin(ident, conn, principal, reauth=True)
        row = (await conn.execute(select(users).where(users.c.user_id == user_id))).first()
        if row is None:
            raise not_found()
        username = row.username
    if password is not None:
        passwords.check_policy(password, username)
        new_hash = await ident.passwords.hash(password)
    async with ident.engine.begin() as conn:
        actor = await authorize_admin(ident, conn, principal, reauth=True)
        row = (await conn.execute(select(users).where(users.c.user_id == user_id))).first()
        if row is None:
            raise not_found()
        now = ident.clock.now()
        values: dict[str, Any] = {"updated_at": now}
        if display_name is not None:
            values["display_name"] = display_name
        deactivated = active is False and row.status == "aktif"
        reactivated = active is True and row.status != "aktif"
        if deactivated:
            if user_id == actor.user_id:
                raise AstriaError("AKSI_DITOLAK", "admin tidak boleh menonaktifkan akunnya sendiri", 422)
            if "admin" in (await roles_of(conn, [user_id]))[user_id] and await count_admins(conn) <= 1:
                raise AstriaError("ADMIN_TERAKHIR", "admin aktif terakhir tidak boleh dinonaktifkan", 422)
            values["status"] = "nonaktif"
        if reactivated:
            values["status"] = "aktif"
        if new_hash is not None:
            values["password_hash"] = new_hash
        await conn.execute(update(users).where(users.c.user_id == user_id).values(**values))
        if deactivated or new_hash is not None:
            await revoke_sessions(conn, user_id, now)
        if deactivated:
            await events.enqueue_revoked(conn, user_id=user_id, reason="akun_nonaktif", at=now)
            await events.enqueue_audit(
                conn,
                events.audit_record(
                    action="identity.user.deactivated",
                    key=f"identity-user-deactivated-{user_id}-{int(now.timestamp() * 1e6)}",
                    actor=actor.user_id,
                    target_type="user",
                    target_id=user_id,
                    payload={"user_id": user_id},
                    occurred_at=now,
                ),
            )
        if reactivated:
            await events.enqueue_audit(
                conn,
                events.audit_record(
                    action="identity.user.activated",
                    key=f"identity-user-activated-{user_id}-{int(now.timestamp() * 1e6)}",
                    actor=actor.user_id,
                    target_type="user",
                    target_id=user_id,
                    payload={"user_id": user_id},
                    occurred_at=now,
                ),
            )
        if new_hash is not None:
            await events.enqueue_revoked(conn, user_id=user_id, reason="kata_sandi_diganti", at=now)
            await events.enqueue_audit(
                conn,
                events.audit_record(
                    action="identity.password.changed",
                    key=f"identity-password-changed-{user_id}-{int(now.timestamp() * 1e6)}",
                    actor=actor.user_id,
                    target_type="user",
                    target_id=user_id,
                    payload={"user_id": user_id, "by_admin": True},
                    occurred_at=now,
                ),
            )
        return await get(conn, user_id)


async def set_roles(
    ident: Identity, principal: ServicePrincipal, user_id: str, role_list: list[str], *, request_id: str
) -> dict[str, Any]:
    role_list = validate_roles(role_list)
    async with ident.engine.begin() as conn:
        actor = await authorize_admin(ident, conn, principal, reauth=True)
        row = (await conn.execute(select(users).where(users.c.user_id == user_id))).first()
        if row is None:
            raise not_found()
        before = (await roles_of(conn, [user_id]))[user_id]
        if before == role_list:
            return to_user(row, before)
        if "admin" in before and "admin" not in role_list and row.status == "aktif" and await count_admins(conn) <= 1:
            raise AstriaError("ADMIN_TERAKHIR", "admin aktif terakhir tidak boleh kehilangan peran admin", 422)
        now = ident.clock.now()
        await conn.execute(delete(user_roles).where(user_roles.c.user_id == user_id))
        await conn.execute(
            insert(user_roles),
            [{"user_id": user_id, "role_code": r, "granted_by": actor.user_id, "granted_at": now} for r in role_list],
        )
        await conn.execute(update(users).where(users.c.user_id == user_id).values(updated_at=now))
        await revoke_sessions(conn, user_id, now)
        await events.enqueue_revoked(conn, user_id=user_id, reason="peran_berubah", at=now, roles_after=role_list)
        # Audit sinkron terakhir sebelum commit: bila gagal, seluruh perubahan dibatalkan.
        await ident.audit.record(
            events.audit_record(
                action="identity.role.changed",
                key=f"identity-role-changed-{request_id}",
                actor=actor.user_id,
                target_type="user",
                target_id=user_id,
                payload={"user_id": user_id, "roles_before": before, "roles_after": role_list, "actor": actor.user_id},
                occurred_at=now,
            )
        )
        return await get(conn, user_id)


async def revoke_all_sessions(ident: Identity, principal: ServicePrincipal, user_id: str) -> None:
    """Admin (dengan re-auth) atau pemilik akun sendiri (tanpa re-auth) mencabut semua sesi."""
    act = principal.act
    async with ident.engine.begin() as conn:
        own = bool(act) and act.get("sub") == user_id
        if own:
            row = (await conn.execute(select(users).where(users.c.user_id == user_id))).first()
            if row is None or row.status != "aktif":
                raise AstriaError("PERAN_TIDAK_CUKUP", "akun tidak aktif", 403)
            actor_id = user_id
        else:
            actor_id = (await authorize_admin(ident, conn, principal, reauth=True)).user_id
            if (await conn.execute(select(users.c.user_id).where(users.c.user_id == user_id))).first() is None:
                raise not_found()
        now = ident.clock.now()
        await revoke_sessions(conn, user_id, now)
        await events.enqueue_revoked(conn, user_id=user_id, reason="sesi_dicabut", at=now)
        await events.enqueue_audit(
            conn,
            events.audit_record(
                action="identity.sessions.revoked",
                key=f"identity-sessions-revoked-{user_id}-{int(now.timestamp() * 1e6)}",
                actor=actor_id,
                target_type="user",
                target_id=user_id,
                payload={"user_id": user_id, "own": own},
                occurred_at=now,
            ),
        )


def username_hash(username: str) -> str:
    return "u:" + sha256_hex(username.lower())
