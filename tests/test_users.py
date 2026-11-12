"""Direktori pengguna minimal (subset identity#4): baca pengguna, seed dev, dan otorisasi token layanan.

Setiap uji HTTP berjalan di SQLite (selalu) dan PostgreSQL (bila ASTRIA_TEST_DATABASE_URL diisi, skema sementara).
"""

import json
import os
import time
import uuid
from pathlib import Path

import orjson
import pytest
from astria_common.auth import issue_service_token, load_or_create_signing_key
from astria_common.envguard import EnvironmentGuardError
from astria_common.hmac_auth import signed_headers
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import text

from astria_identity.main import build_app
from astria_identity.settings import Settings
from astria_identity.users import Seed, User, apply_seed, get_user, load_seed

PG_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
API_KEY = bytes(range(32, 64))
DEV01 = {
    "user_id": "usr_dev01",
    "username": "analis.dev",
    "display_name": "Analis Dev",
    "roles": ["analis"],
    "active": True,
}
NONAKTIF = {"user_id": "usr_lama01", "username": "lama", "display_name": "Akun Lama", "roles": [], "active": False}


def write_seed(path: Path, users: list[dict]) -> Path:
    path.write_text(json.dumps({"users": users}), encoding="utf-8")
    return path


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="tanpa PG"))])
def db(request: pytest.FixtureRequest, tmp_path: Path) -> dict:
    if request.param == "sqlite":
        return {"database_url": SecretStr(f"sqlite+aiosqlite:///{tmp_path}/identity_test.db")}
    return {"database_url": SecretStr(PG_URL or ""), "db_schema": f"t_{uuid.uuid4().hex[:8]}"}


@pytest.fixture
def client(tmp_path: Path, db: dict):
    keys = tmp_path / "service-keys.json"
    keys.write_text(json.dumps({"api": API_KEY.hex()}), encoding="utf-8")
    settings = Settings(
        env="test",
        signing_key_path=tmp_path / "signing.pem",
        service_keys_file=keys,
        identity_seed_file=write_seed(tmp_path / "seed.json", [DEV01, NONAKTIF]),
        **db,
    )
    app = build_app(settings)
    with TestClient(app) as c:
        deadline = time.monotonic() + 10
        while (ready := c.get("/ready")).status_code != 200 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.status_code == 200, ready.text
        yield c
        if "db_schema" in db:
            c.portal.call(_drop, app.state.db.engine, db["db_schema"])


async def _drop(engine, schema: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def bearer(tmp_path: Path, subject: str = "svc:api", audience: str = "svc:identity") -> dict[str, str]:
    token, _ = issue_service_token(
        load_or_create_signing_key(tmp_path / "signing.pem"), subject=subject, audience=audience
    )
    return {"Authorization": f"Bearer {token}"}


def test_seeded_user_is_returned(client: TestClient, tmp_path: Path) -> None:
    resp = client.get("/internal/v1/users/usr_dev01", headers=bearer(tmp_path))
    assert resp.status_code == 200, resp.text
    assert resp.json() == DEV01
    assert client.get("/internal/v1/users/usr_lama01", headers=bearer(tmp_path)).json()["active"] is False


def test_token_from_own_issuer_flow(client: TestClient) -> None:
    """Seperti api: minta token `svc:identity` lewat HMAC, lalu baca pengguna (verifikasi dengan kunci sendiri)."""
    path = "/internal/v1/service-tokens"
    raw = orjson.dumps({"audience": "svc:identity"})
    headers = signed_headers("api", API_KEY, "POST", path, raw) | {"Content-Type": "application/json"}
    token = client.post(path, content=raw, headers=headers).json()["token"]
    resp = client.get("/internal/v1/users/usr_dev01", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text


def test_unknown_user_is_404(client: TestClient, tmp_path: Path) -> None:
    resp = client.get("/internal/v1/users/usr_tidakada", headers=bearer(tmp_path))
    assert (resp.status_code, resp.json()["error"]["code"]) == (404, "PENGGUNA_TIDAK_DITEMUKAN")
    assert set(resp.json()["error"]) == {"code", "message", "trace_id"}


def test_invalid_user_id_is_400(client: TestClient, tmp_path: Path) -> None:
    assert client.get("/internal/v1/users/admin'--", headers=bearer(tmp_path)).status_code == 400


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer bukan-token"}])
def test_requires_service_token(client: TestClient, headers: dict) -> None:
    assert client.get("/internal/v1/users/usr_dev01", headers=headers).status_code == 401


def test_only_api_may_read_users(client: TestClient, tmp_path: Path) -> None:
    resp = client.get("/internal/v1/users/usr_dev01", headers=bearer(tmp_path, subject="svc:gateway"))
    assert (resp.status_code, resp.json()["error"]["code"]) == (403, "PEMANGGIL_DITOLAK")
    resp = client.get("/internal/v1/users/usr_dev01", headers=bearer(tmp_path, audience="svc:config"))
    assert (resp.status_code, resp.json()["error"]["code"]) == (403, "AUDIENS_SALAH")


def test_seed_is_idempotent_and_replaces_roles(client: TestClient) -> None:
    engine = client.app.state.db.engine
    changed = Seed(users=[User(**(DEV01 | {"display_name": "Analis Baru", "roles": ["dfir", "admin"]}))])

    async def run() -> User | None:
        for seed in (changed, changed):
            async with engine.begin() as conn:
                await apply_seed(conn, seed)
        async with engine.connect() as conn:
            return await get_user(conn, "usr_dev01")

    user = client.portal.call(run)
    assert user is not None
    assert (user.display_name, user.roles) == ("Analis Baru", ["admin", "dfir"])


def test_prod_refuses_seed_file(tmp_path: Path) -> None:
    settings = Settings(
        env="prod",
        database_url=SecretStr("postgresql+psycopg://u:p@postgres:5432/identity"),
        identity_seed_file=write_seed(tmp_path / "seed.json", [DEV01]),
    )
    with pytest.raises(EnvironmentGuardError, match="seed"):
        build_app(settings)


def test_seed_without_database_refuses_to_start(tmp_path: Path) -> None:
    settings = Settings(env="test", identity_seed_file=write_seed(tmp_path / "seed.json", [DEV01]))
    with pytest.raises(RuntimeError, match="ASTRIA_DATABASE_URL"):
        build_app(settings)


@pytest.mark.parametrize(
    "users",
    [
        [DEV01 | {"roles": ["juri"]}],
        [DEV01 | {"user_id": "dev01"}],
        [DEV01 | {"extra": 1}],
        [DEV01, DEV01 | {"user_id": "usr_dev02"}],
    ],
)
def test_load_seed_rejects_bad_files(tmp_path: Path, users: list[dict]) -> None:
    with pytest.raises((ValidationError, ValueError)):
        load_seed(write_seed(tmp_path / "seed.json", users))
