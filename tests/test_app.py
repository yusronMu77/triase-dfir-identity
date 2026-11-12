"""Perakitan aplikasi: /health, /ready, pagar lingkungan, dan seed yang idempoten."""

from pathlib import Path

import pytest
from astria_common.envguard import EnvironmentGuardError
from conftest import ADMIN_ID, Env, make_env, reopen
from pydantic import SecretStr
from sqlalchemy import func, select

from astria_identity.main import build_app
from astria_identity.settings import Settings
from astria_identity.tables import roles, service_keys, users


def test_health_ready_and_metrics(env: Env) -> None:
    health = env.client.get("/health").json()
    assert health["service"] == "identity" and health["env"] == "test"
    assert env.client.get("/ready").status_code == 200
    text = env.client.get("/metrics").text
    assert "astria_service_info" in text
    assert "identity_sessions_active" in text


def test_database_is_required(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="ASTRIA_DATABASE_URL"):
        build_app(Settings(env="test", signing_key_path=tmp_path / "signing.pem"))


def test_refuses_to_start_with_non_dev_database_in_dev() -> None:
    url = SecretStr("postgresql+psycopg://u:p@postgres:5432/astria")
    with pytest.raises(EnvironmentGuardError):
        build_app(Settings(env="dev", database_url=url))


def test_seed_users_are_forbidden_in_prod(tmp_path: Path) -> None:
    seed = tmp_path / "seed.json"
    seed.write_text("[]", encoding="utf-8")
    url = SecretStr("postgresql+psycopg://u:p@postgres:5432/astria")
    with pytest.raises(RuntimeError, match="SEED_USERS"):
        build_app(Settings(env="prod", database_url=url, seed_users_file=seed, signing_key_path=tmp_path / "s.pem"))


def test_restart_is_idempotent(tmp_path: Path) -> None:
    first = make_env(tmp_path)
    first.client.__exit__(None, None, None)
    second = reopen(first)  # DB, kunci, dan berkas seed yang sama
    try:

        async def counts() -> list[int]:
            out = []
            async with second.ident.engine.connect() as conn:
                for table in (roles, users, service_keys):
                    out.append((await conn.execute(select(func.count()).select_from(table))).scalar_one())
            return out

        assert second.client.portal.call(counts) == [4, 2, 4]
        assert second.login("admin1", first.passwords["admin1"]).status_code == 200
        assert second.call("GET", f"/users/{ADMIN_ID}").status_code == 200
    finally:
        second.client.__exit__(None, None, None)


def test_service_key_secrets_are_encrypted_at_rest(env: Env) -> None:
    async def blobs() -> list[bytes]:
        async with env.ident.engine.connect() as conn:
            return [bytes(r.secret_enc) for r in (await conn.execute(select(service_keys))).all()]

    stored = env.client.portal.call(blobs)
    assert len(stored) == 4
    for secret in env.service_keys.values():
        assert all(secret not in blob and secret.hex().encode() not in blob for blob in stored)
