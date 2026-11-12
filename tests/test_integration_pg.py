"""Integrasi PostgreSQL nyata. Butuh `ASTRIA_TEST_DATABASE_URL`; tiap uji memakai skema sendiri lalu menghapusnya.

Contoh (di kontainer `py` devenv): ASTRIA_TEST_DATABASE_URL=postgresql+psycopg://astria_dev:...@postgres:5432/postgres
"""

import asyncio
import hashlib
import os
import secrets
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import ANALIS_ID, Env, make_env, outbox_rows
from pydantic import SecretStr
from sqlalchemy import func, inspect, select, text
from sqlalchemy.ext.asyncio import create_async_engine

from astria_identity import pairing
from astria_identity.tables import metadata, user_roles, users

URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="ASTRIA_TEST_DATABASE_URL tidak diisi")


def _drop_schema(schema: str) -> None:
    async def go() -> None:
        engine = create_async_engine(URL.replace("postgresql://", "postgresql+psycopg://"))  # type: ignore[union-attr]
        async with engine.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await engine.dispose()

    asyncio.run(go())


@pytest.fixture
def pg(tmp_path: Path) -> Iterator[Env]:
    schema = "idt_" + uuid.uuid4().hex[:12]
    env = make_env(tmp_path, database_url=SecretStr(URL), db_schema=schema)  # type: ignore[arg-type]
    try:
        yield env
    finally:
        env.client.__exit__(None, None, None)
        _drop_schema(schema)


def test_schema_is_created_from_empty_and_bootstrap_completes(pg: Env) -> None:
    assert pg.client.get("/ready").json()["status"] == "ok"

    async def tables() -> set[str]:
        async with pg.ident.engine.connect() as conn:
            return set(await conn.run_sync(lambda c: inspect(c).get_table_names(schema=pg.settings.db_schema)))

    assert {t.name for t in metadata.sorted_tables} <= pg.client.portal.call(tables)
    assert pg.login("analis1").status_code == 200


def test_username_is_unique_case_insensitively_at_database_level(pg: Env) -> None:
    from sqlalchemy.exc import IntegrityError

    async def dup() -> None:
        async with pg.ident.engine.begin() as conn:
            await conn.execute(
                users.insert().values(
                    user_id="usr_DUPLIKATAAAA",
                    username="ANALIS1",
                    username_lower="analis1",
                    display_name="x",
                    status="aktif",
                    password_hash="x",
                    created_at=pg.clock.now(),
                    updated_at=pg.clock.now(),
                )
            )

    with pytest.raises(IntegrityError):
        pg.client.portal.call(dup)


def test_concurrent_pairing_claims_only_one_wins(pg: Env) -> None:
    analis = pg.session("analis1")
    code = pg.call("POST", "/pairing-codes", {"channel": "whatsapp"}, act=analis["act"]).json()["code"]
    exts = [hashlib.sha256(f"wa:{i}".encode()).hexdigest() for i in range(8)]

    async def race() -> list[str]:
        async def one(ext: str) -> str:
            try:
                await pairing.claim(pg.ident, channel="whatsapp", external_id_hash=ext, code=code)
                return "ok"
            except Exception as exc:  # noqa: BLE001
                return getattr(exc, "code", type(exc).__name__)

        return list(await asyncio.gather(*(one(e) for e in exts)))

    results = pg.client.portal.call(race)
    assert results.count("ok") == 1, results
    assert len(results) == 8


def test_audit_failure_leaves_no_user_and_no_outbox_rows(pg: Env) -> None:
    admin = pg.session("admin1", reauth=True)
    before = len(outbox_rows(pg))
    pg.audit.fail = True
    body = {
        "username": "gagal.audit",
        "display_name": "G",
        "password": secrets.token_urlsafe(18),
        "roles": ["analis"],
    }
    assert pg.call("POST", "/users", body, act=admin["act"]).status_code == 503
    pg.audit.fail = False

    async def count() -> int:
        async with pg.ident.engine.connect() as conn:
            return (await conn.execute(select(func.count()).select_from(users))).scalar_one()

    assert pg.client.portal.call(count) == 2
    assert len(outbox_rows(pg)) == before


def test_role_change_writes_event_in_same_transaction_as_the_change(pg: Env) -> None:
    admin = pg.session("admin1", reauth=True)
    assert pg.call("PUT", f"/users/{ANALIS_ID}/roles", {"roles": ["dfir"]}, act=admin["act"]).status_code == 200
    events = outbox_rows(pg, "identity.revoked")
    assert events and events[-1]["envelope"]["data"]["roles_after"] == ["dfir"]

    async def roles() -> list[str]:
        async with pg.ident.engine.connect() as conn:
            rows = await conn.execute(select(user_roles.c.role_code).where(user_roles.c.user_id == ANALIS_ID))
            return [r.role_code for r in rows]

    assert pg.client.portal.call(roles) == ["dfir"]


def test_concurrent_logins_and_throttle_counts_are_consistent(pg: Env) -> None:
    async def hammer() -> list[int]:
        from astria_identity import sessions

        async def attempt() -> int:
            try:
                await sessions.login(
                    pg.ident, username="analis1", password="salah-salah-salah-1", ip_hash=None, ua_hash=None
                )
            except Exception as exc:  # noqa: BLE001
                return getattr(exc, "status", 0)
            return 200

        return list(await asyncio.gather(*(attempt() for _ in range(10))))

    statuses = pg.client.portal.call(hammer)
    assert set(statuses) <= {401, 429}
    assert statuses.count(401) >= pg.settings.login_fail_limit_user  # semua percobaan awal tercatat
    assert pg.login("analis1").status_code == 429
