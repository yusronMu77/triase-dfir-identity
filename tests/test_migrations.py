"""Migrasi Alembic: baseline dari kosong sama dengan metadata, stamp untuk skema lama tanpa DDL, dan idempoten.

SQLite selalu jalan. PostgreSQL butuh `ASTRIA_TEST_DATABASE_URL`; tiap uji memakai skema sendiri lalu menghapusnya.
"""

import asyncio
import os
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from conftest import make_env
from pydantic import SecretStr
from sqlalchemy import func, insert, inspect, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from astria_identity import cli
from astria_identity.migrate import MIGRATIONS_DIR, TARGET_METADATA, VERSION_TABLE, MigrationError, migrate_sync
from astria_identity.tables import roles
from astria_identity.tables import users as users_table

PG_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
HEAD = "0001_baseline"


async def _with_conn(url: str, schema: str | None, fn: Callable[[Connection], Any]) -> Any:
    kwargs: dict[str, Any] = {"connect_args": {"options": f"-csearch_path={schema}"}} if schema else {}
    engine = create_async_engine(url, **kwargs)
    try:
        async with engine.begin() as conn:
            return await conn.run_sync(fn)
    finally:
        await engine.dispose()


def run(url: str, fn: Callable[[Connection], Any], schema: str | None = None) -> Any:
    return asyncio.run(_with_conn(url, schema, fn))


def _sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


def _revision(conn: Connection, schema: str | None = None) -> str | None:
    return MigrationContext.configure(conn, opts={"version_table_schema": schema}).get_current_revision()


def _diff(conn: Connection, schema: str | None = None) -> list[Any]:
    ctx = MigrationContext.configure(conn, opts={"version_table_schema": schema})
    return compare_metadata(ctx, TARGET_METADATA)


def test_script_head_is_baseline() -> None:
    assert ScriptDirectory(str(MIGRATIONS_DIR)).get_current_head() == HEAD


def test_baseline_from_empty_matches_metadata(tmp_path: Path) -> None:
    url = _sqlite_url(tmp_path / "kosong.db")
    assert run(url, lambda c: migrate_sync(c, None)) == "create"
    assert run(url, _diff) == []
    assert run(url, _revision) == HEAD


def test_upgrade_on_current_schema_is_noop(tmp_path: Path) -> None:
    url = _sqlite_url(tmp_path / "idempoten.db")
    assert run(url, lambda c: migrate_sync(c, None)) == "create"
    assert run(url, lambda c: migrate_sync(c, None)) == "upgrade"
    assert run(url, lambda c: migrate_sync(c, None)) == "upgrade"
    assert run(url, _diff) == []
    assert run(url, _revision) == HEAD


def test_existing_dev_schema_is_stamped_without_ddl(tmp_path: Path) -> None:
    """DB yang dibuat lewat create_all (Tahap 0 dan 4): data tetap, tidak ada tabel yang dibuat ulang."""
    url = _sqlite_url(tmp_path / "dev.db")

    def legacy(conn: Connection) -> None:
        TARGET_METADATA.create_all(conn)
        conn.execute(insert(roles).values(role_code="analis", description="uji"))

    run(url, legacy)
    tables_before = run(url, lambda c: sorted(inspect(c).get_table_names()))

    assert run(url, lambda c: migrate_sync(c, None)) == "stamp"
    assert run(url, _revision) == HEAD
    assert run(url, lambda c: sorted(inspect(c).get_table_names())) == sorted([*tables_before, VERSION_TABLE])
    assert run(url, lambda c: c.execute(select(func.count()).select_from(roles)).scalar_one()) == 1
    assert run(url, _diff) == []

    # Setelah di-stamp, upgrade berikutnya tidak mengubah apa pun.
    assert run(url, lambda c: migrate_sync(c, None)) == "upgrade"
    assert run(url, lambda c: c.execute(select(func.count()).select_from(roles)).scalar_one()) == 1


def test_partial_schema_is_refused_and_untouched(tmp_path: Path) -> None:
    url = _sqlite_url(tmp_path / "sebagian.db")
    run(url, lambda c: users_table.create(c))

    with pytest.raises(MigrationError, match="tabel hilang"):
        run(url, lambda c: migrate_sync(c, None))

    names = run(url, lambda c: set(inspect(c).get_table_names()))
    assert names == {"users"}


def test_stamp_only_refuses_empty_schema(tmp_path: Path) -> None:
    url = _sqlite_url(tmp_path / "stamp-kosong.db")
    with pytest.raises(MigrationError, match="skema kosong"):
        run(url, lambda c: migrate_sync(c, None, stamp_only=True))
    assert run(url, lambda c: set(inspect(c).get_table_names())) == set()


def test_startup_creates_baseline_on_empty_database(tmp_path: Path) -> None:
    """Jalur produksi: `Migrations` di start aplikasi, bukan create_all."""
    url = _sqlite_url(tmp_path / "startup.db")
    env = make_env(tmp_path, database_url=SecretStr(url))
    try:
        assert env.client.get("/ready").status_code == 200
    finally:
        env.client.__exit__(None, None, None)
    assert run(url, _revision) == HEAD
    assert run(url, _diff) == []


def test_startup_stamps_existing_database(tmp_path: Path) -> None:
    url = _sqlite_url(tmp_path / "startup-lama.db")
    run(url, lambda c: TARGET_METADATA.create_all(c))
    env = make_env(tmp_path, database_url=SecretStr(url))
    try:
        assert env.client.get("/ready").status_code == 200
        assert env.ident.schema_ready.is_set()
    finally:
        env.client.__exit__(None, None, None)
    assert run(url, _revision) == HEAD


def test_cli_migrate_creates_then_reports_upgrade(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    url = _sqlite_url(tmp_path / "cli.db")
    monkeypatch.setenv("ASTRIA_ENV", "test")
    monkeypatch.setenv("ASTRIA_DATABASE_URL", url)
    monkeypatch.setenv("ASTRIA_SIGNING_KEY_PATH", str(tmp_path / "signing.pem"))
    assert cli.main(["migrate"]) == 0
    assert "skema baru dibuat dari baseline" in capsys.readouterr().out
    assert cli.main(["migrate"]) == 0
    assert "migrasi dijalankan sampai head" in capsys.readouterr().out
    assert run(url, _diff) == []


def test_cli_migrate_stamp_refuses_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("ASTRIA_ENV", "test")
    monkeypatch.setenv("ASTRIA_DATABASE_URL", _sqlite_url(tmp_path / "cli-stamp.db"))
    monkeypatch.setenv("ASTRIA_SIGNING_KEY_PATH", str(tmp_path / "signing.pem"))
    assert cli.main(["migrate", "--stamp"]) == 1
    assert "GAGAL [MIGRASI]" in capsys.readouterr().err


# --- PostgreSQL (skema sementara) ---


@pytest.fixture
def pg_schema() -> Iterator[str]:
    schema = "idm_" + uuid.uuid4().hex[:12]
    run(PG_URL, lambda c: c.execute(text(f'CREATE SCHEMA "{schema}"')))
    try:
        yield schema
    finally:
        run(PG_URL, lambda c: c.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')))


pg_only = pytest.mark.skipif(not PG_URL, reason="ASTRIA_TEST_DATABASE_URL tidak diisi")


@pg_only
def test_pg_baseline_from_empty_matches_metadata(pg_schema: str) -> None:
    assert run(PG_URL, lambda c: migrate_sync(c, pg_schema), pg_schema) == "create"
    assert run(PG_URL, _diff, pg_schema) == []
    assert run(PG_URL, _revision, pg_schema) == HEAD


@pg_only
def test_pg_existing_schema_is_stamped(pg_schema: str) -> None:
    run(PG_URL, lambda c: TARGET_METADATA.create_all(c), pg_schema)
    assert run(PG_URL, lambda c: migrate_sync(c, pg_schema), pg_schema) == "stamp"
    assert run(PG_URL, _revision, pg_schema) == HEAD
    assert run(PG_URL, _diff, pg_schema) == []


@pg_only
def test_pg_startup_runs_baseline(tmp_path: Path, pg_schema: str) -> None:
    env = make_env(tmp_path, database_url=SecretStr(PG_URL), db_schema=pg_schema)
    try:
        assert env.client.get("/ready").status_code == 200
    finally:
        env.client.__exit__(None, None, None)
    assert run(PG_URL, _revision, pg_schema) == HEAD
    assert run(PG_URL, _diff, pg_schema) == []
