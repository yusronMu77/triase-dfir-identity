"""Token layanan (JWT EdDSA) dan kunci HMAC layanan: penerbitan, matriks audiens, klaim `act`, JWKS, rotasi."""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any

from astria_common.auth import ServicePrincipal, issue_service_token
from astria_common.errors import AstriaError
from astria_common.hmac_auth import HmacError, verify
from astria_common.log import get_logger
from astria_contracts.openapi.identity_internal import ServiceTokenRequest
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_identity import events, metrics, users
from astria_identity.core import Identity
from astria_identity.keys import jwk_from_public, service_key_rows
from astria_identity.tables import service_keys, sessions, signing_keys
from astria_identity.tables import users as users_t

log = get_logger(__name__)


def key_aad(service: str, key_id: str) -> bytes:
    return f"{service}:{key_id}".encode()


def new_key_id() -> str:
    return "svk_" + secrets.token_hex(6)


async def jwks(ident: Identity) -> dict[str, Any]:
    """Kunci aktif ditambah kunci overlap yang belum lewat batas; bila DB mati, hanya kunci yang termuat."""
    signing = ident.keys.signing
    if signing is None:
        raise AstriaError("KUNCI_TIDAK_TERSEDIA", "kunci penandatanganan tidak tersedia", 503)
    keys = {signing.kid: signing.public_jwk()}
    if ident.db.is_ready:
        now = ident.clock.now()
        try:
            async with ident.engine.connect() as conn:
                rows = (
                    await conn.execute(select(signing_keys).where(signing_keys.c.status.in_(("aktif", "overlap"))))
                ).all()
        except Exception:  # noqa: BLE001 - JWKS tetap melayani kunci yang termuat
            rows = []
            log.warning("jwks_tanpa_basis_data")
        for row in rows:
            if row.kid not in keys and (row.not_after is None or row.not_after > now):
                keys[row.kid] = jwk_from_public(row.kid, bytes(row.public_key))
    return {"keys": list(keys.values())}


async def _verify_hmac(
    ident: Identity,
    conn: AsyncConnection,
    service: str,
    method: str,
    path: str,
    headers: Any,
    body: bytes,
) -> None:
    rows = await service_key_rows(conn, service, ident.clock.now())
    if not rows:
        raise HmacError("layanan_tidak_dikenal")
    last: HmacError | None = None
    for row in rows:
        secret = ident.keys.decrypt_secret(bytes(row.secret_enc), aad=key_aad(service, row.key_id))
        try:
            verify(secret, method, path, headers, body, ident.nonces)
            return
        except HmacError as exc:
            if exc.reason in {
                "nonce_terpakai",
                "cap_waktu_di_luar_jendela",
                "header_tidak_lengkap",
                "nonce_tidak_valid",
            }:
                raise  # bukan soal kunci mana; mencoba kunci lain tidak membantu
            last = exc
    raise last or HmacError("tanda_tangan_salah")


async def _resolve_act(ident: Identity, conn: AsyncConnection, act: dict[str, Any]) -> dict[str, Any]:
    """Pastikan pengguna ada dan aktif, ganti `roles` dengan peran saat ini, isi `reauth_at` dari sesi (bila ada)."""
    user_id = act["sub"]
    row = (await conn.execute(select(users_t.c.status).where(users_t.c.user_id == user_id))).first()
    if row is None or row.status != "aktif":
        raise AstriaError("ACT_DITOLAK", "pengguna pada klaim act tidak dikenal atau tidak aktif", 403)
    out: dict[str, Any] = {"sub": user_id, "roles": (await users.roles_of(conn, [user_id]))[user_id]}
    session_id = act.get("session_id")
    if session_id:
        now = ident.clock.now()
        sess = (
            await conn.execute(
                select(sessions).where(sessions.c.session_id == session_id, sessions.c.user_id == user_id)
            )
        ).first()
        if sess is None or sess.revoked_at is not None or sess.idle_expires_at <= now or sess.abs_expires_at <= now:
            raise AstriaError("ACT_DITOLAK", "sesi pada klaim act tidak aktif", 403)
        out["session_id"] = session_id
        if sess.reauth_at is not None:
            out["reauth_at"] = sess.reauth_at.isoformat().replace("+00:00", "Z")
    return out


async def issue(
    ident: Identity, *, service: str, method: str, path: str, headers: Any, body: bytes
) -> tuple[str, datetime]:
    settings = ident.settings
    signing = ident.keys.signing
    if signing is None:
        raise AstriaError("KUNCI_TIDAK_TERSEDIA", "kunci penandatanganan tidak tersedia", 503)

    async with ident.engine.connect() as conn:
        try:
            await _verify_hmac(ident, conn, service, method, path, headers, body)
        except HmacError as exc:
            metrics.TOKEN_REJECTED.labels("hmac").inc()
            log.warning("token_layanan_ditolak", service=service or "-", reason=exc.reason)
            raise AstriaError("HMAC_TIDAK_VALID", "permintaan token tidak terautentikasi", 401) from exc

        try:
            req = ServiceTokenRequest.model_validate_json(body)
        except ValueError as exc:
            metrics.TOKEN_REJECTED.labels("validasi").inc()
            raise AstriaError("VALIDASI_GAGAL", "isi permintaan token tidak valid", 400) from exc

        if req.audience == f"svc:{service}":
            metrics.TOKEN_REJECTED.labels("diri_sendiri").inc()
            raise AstriaError("AUDIENS_DITOLAK", "token untuk diri sendiri tidak diterbitkan", 403)
        if not ident.audience_allowed(service, req.audience):
            metrics.TOKEN_REJECTED.labels("audiens").inc()
            log.warning("audiens_ditolak", service=service, audience=req.audience)
            await _audit_denied(ident, service, req.audience)
            raise AstriaError("AUDIENS_DITOLAK", "layanan ini tidak boleh meminta token untuk audiens itu", 403)

        act: dict[str, Any] | None = None
        if req.act is not None:
            if service not in settings.act_callers:
                metrics.TOKEN_REJECTED.labels("act").inc()
                raise AstriaError("ACT_DITOLAK", "layanan ini tidak boleh membawa klaim pengguna", 403)
            try:
                act = await _resolve_act(ident, conn, req.act.model_dump(exclude_none=True))
            except AstriaError:
                metrics.TOKEN_REJECTED.labels("act").inc()
                raise

    token, expires = issue_service_token(
        signing, subject=f"svc:{service}", audience=req.audience, act=act, ttl=settings.token_ttl_seconds
    )
    metrics.TOKEN_ISSUED.labels(service).inc()
    log.info("token_layanan_terbit", service=service, audience=req.audience, with_act=bool(act))
    return token, expires


async def _audit_denied(ident: Identity, service: str, audience: str) -> None:
    """Penolakan audiens dicatat asinkron; kegagalan mencatat tidak boleh mengubah jawaban 403."""
    try:
        now = ident.clock.now()
        async with ident.engine.begin() as conn:
            await events.enqueue_audit(
                conn,
                events.audit_record(
                    action="identity.token.denied",
                    key=f"identity-token-denied-{events.new_request_id()}",
                    actor=f"svc:{service}",
                    target_type="audience",
                    target_id=audience,
                    payload={"service": service, "audience": audience},
                    occurred_at=now,
                ),
            )
    except Exception:  # noqa: BLE001
        log.warning("audit_penolakan_gagal")


async def rotate_service_key(
    ident: Identity, principal: ServicePrincipal, service: str, *, request_id: str
) -> dict[str, Any]:
    async with ident.engine.begin() as conn:
        actor = await users.authorize_admin(ident, conn, principal, reauth=True)
        now = ident.clock.now()
        current = (
            await conn.execute(
                select(service_keys)
                .where(service_keys.c.service == service, service_keys.c.status == "aktif")
                .order_by(service_keys.c.created_at.desc())
            )
        ).all()
        known = (
            current
            or (
                await conn.execute(select(service_keys.c.key_id).where(service_keys.c.service == service).limit(1))
            ).all()
        )
        if not known:
            raise AstriaError("LAYANAN_TIDAK_DITEMUKAN", "layanan tidak punya kunci terdaftar", 404)
        previous = current[0] if current else None
        not_after = now + ident.overlap
        if current:
            await conn.execute(
                update(service_keys)
                .where(service_keys.c.service == service, service_keys.c.status == "aktif")
                .values(status="overlap", not_after=not_after)
            )
        key_id = new_key_id()
        secret = secrets.token_bytes(32)
        await conn.execute(
            insert(service_keys).values(
                key_id=key_id,
                service=service,
                status="aktif",
                secret_enc=ident.keys.encrypt_secret(secret, aad=key_aad(service, key_id)),
                created_at=now,
                not_after=None,
            )
        )
        # Audit sinkron terakhir sebelum commit: bila gagal, kunci lama tetap satu-satunya yang aktif.
        await ident.audit.record(
            events.audit_record(
                action="identity.key.rotated",
                key=f"identity-key-rotated-{request_id}",
                actor=actor.user_id,
                target_type="service_key",
                target_id=service,
                payload={
                    "key_kind": "service_hmac",
                    "service": service,
                    "key_id": key_id,
                    "previous_key_id": previous.key_id if previous else "",
                },
                occurred_at=now,
            )
        )
    log.info("kunci_layanan_dirotasi", service=service, key_id=key_id, by=actor.user_id)
    return {
        "service": service,
        "key_id": key_id,
        "key": secret.hex(),
        "previous_key_id": previous.key_id if previous else None,
        "previous_not_after": not_after if previous else None,
    }
