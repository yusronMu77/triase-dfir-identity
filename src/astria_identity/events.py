"""Event dan catatan audit identity.

- Audit SINKRON (fail-closed) lewat `AuditSink.record` untuk aksi kritis: dipanggil di dalam transaksi sebelum commit,
  sehingga bila audit tidak tersedia perubahan ikut dibatalkan.
- Audit ASINKRON dan `identity.revoked` lewat outbox di transaksi yang sama dengan perubahan datanya.
- Payload tidak pernah memuat kata sandi, token sesi, kode pairing, atau nilai kunci (audit menolak kunci terlarang).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol

from astria_common import outbox
from astria_common.audit_client import AuditClient, audit_event
from astria_common.auth import SigningKey, issue_service_token
from astria_common.events import new_event
from astria_contracts.events.audit_record import AuditRecord
from sqlalchemy.ext.asyncio import AsyncConnection

SERVICE_ACTOR = "svc:identity"


class AuditSink(Protocol):
    async def record(self, record: AuditRecord | Mapping[str, Any]) -> Any: ...


class LocalTokens:
    """Sumber token untuk AuditClient: identity menandatangani sendiri, tanpa HTTP ke dirinya."""

    def __init__(self, signing: Any, ttl: int) -> None:
        self._signing = signing  # callable -> SigningKey; kunci bisa berganti saat rotasi
        self._ttl = ttl

    async def auth_headers(self, audience: str, act: dict[str, Any] | None = None) -> dict[str, str]:
        key: SigningKey = self._signing()
        token, _ = issue_service_token(key, subject=SERVICE_ACTOR, audience=audience, act=act, ttl=self._ttl)
        return {"Authorization": f"Bearer {token}"}


def make_audit_client(audit_url: str, signing: Any, ttl: int) -> AuditClient:
    return AuditClient(LocalTokens(signing, ttl), audit_url)  # type: ignore[arg-type]


def new_request_id() -> str:
    return uuid.uuid4().hex


def audit_record(
    *,
    action: str,
    key: str,
    actor: str,
    target_type: str,
    target_id: str,
    payload: Mapping[str, Any],
    occurred_at: datetime,
    via: str = "api",
) -> AuditRecord:
    return AuditRecord(
        idempotency_key=key[:200],
        occurred_at=occurred_at,
        actor=actor,
        actor_type="service" if actor.startswith("svc:") else "user",
        action=action,
        target_type=target_type,
        target_id=target_id,
        via=via,  # type: ignore[arg-type]
        payload=dict(payload),
    )


async def enqueue_audit(conn: AsyncConnection, record: AuditRecord) -> None:
    """Jalur asinkron: `audit.record` ke outbox dalam transaksi pemanggil."""
    await outbox.enqueue(conn, audit_event(record))


async def enqueue_revoked(
    conn: AsyncConnection,
    *,
    user_id: str,
    reason: str,
    at: datetime,
    roles_after: list[str] | None = None,
) -> None:
    data: dict[str, Any] = {"user_id": user_id, "reason": reason, "revoked_at": at}
    if roles_after is not None:
        data["roles_after"] = roles_after
    event = new_event("identity.revoked", _jsonable(data), occurred_at=at)
    await outbox.enqueue(conn, event)


def _jsonable(data: dict[str, Any]) -> dict[str, Any]:
    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in data.items()}
