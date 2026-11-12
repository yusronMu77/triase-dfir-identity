"""Rakit aplikasi identity: basis data, migrasi, kunci, bootstrap, janitor, dan rute internal.

Basis data (`ASTRIA_DATABASE_URL`) wajib: akun, sesi, dan kunci layanan disimpan di sana.
"""

from __future__ import annotations

from astria_common.app import create_app
from astria_common.auth import JwksSource, ServiceTokenVerifier
from astria_common.db import Database
from astria_common.errors import error_body
from astria_common.events import EventBus
from astria_common.outbox import OutboxRelay
from astria_common.service import Runtime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from astria_identity import tokens
from astria_identity.bootstrap import Bootstrap
from astria_identity.clock import Clock
from astria_identity.core import Identity
from astria_identity.events import AuditSink, make_audit_client
from astria_identity.janitor import Janitor
from astria_identity.keys import KeyStore
from astria_identity.migrate import Migrations
from astria_identity.passwords import Passwords
from astria_identity.routes import routers
from astria_identity.settings import Settings
from astria_identity.throttle import Throttled


def build_app(
    settings: Settings | None = None, *, audit: AuditSink | None = None, clock: Clock | None = None
) -> FastAPI:
    """`audit` dan `clock` hanya untuk uji; produksi memakai klien audit nyata dan jam sistem."""
    settings = settings or Settings()
    if settings.env == "prod" and settings.seed_users_file is not None:
        raise RuntimeError("ASTRIA_SEED_USERS_FILE dilarang di produksi")

    # Skema dibuat lewat migrasi Alembic (`Migrations`), bukan `create_all`. Komposisinya sama dengan
    # `standard_runtime`, tanpa metadata untuk create_all.
    runtime = Runtime(settings)
    if settings.database_url is not None:
        runtime.db = Database(settings.database_url, schema=settings.db_schema)
        if settings.nats_url:
            runtime.bus = EventBus(settings.nats_url, client_name=f"astria-{settings.service_name}")
            runtime.relay = OutboxRelay(runtime.db, runtime.bus)
    db = runtime.require_db()
    keys = KeyStore(settings)
    if audit is None:
        audit = make_audit_client(settings.audit_url, lambda: keys.signing, settings.token_ttl_seconds)
    ident = Identity(
        settings=settings,
        db=db,
        keys=keys,
        passwords=Passwords(
            memory_kib=settings.argon2_memory_kib,
            time_cost=settings.argon2_time_cost,
            parallelism=settings.argon2_parallelism,
        ),
        audit=audit,
        clock=clock or Clock(),
    )
    runtime.add(keys)
    runtime.add(Migrations(ident))
    runtime.add(Bootstrap(ident))
    runtime.add(Janitor(ident))

    app = create_app(
        settings,
        components=runtime.components,
        routers=routers,
        token_verifier=ServiceTokenVerifier(JwksSource(settings.identity_url, fetch=lambda: tokens.jwks(ident))),
    )
    app.state.identity = ident

    @app.exception_handler(Throttled)
    async def _throttled(_request: Request, exc: Throttled) -> JSONResponse:
        return JSONResponse(
            error_body(exc.code, exc.message), status_code=exc.status, headers={"Retry-After": str(exc.retry_after)}
        )

    return app
