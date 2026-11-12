"""Perintah operator: bootstrap-admin, rotate-signing-key, verify-config."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from astria_identity import cli
from astria_identity.main import build_app
from astria_identity.settings import Settings


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = {
        "ASTRIA_ENV": "test",
        "ASTRIA_DATABASE_URL": f"sqlite+aiosqlite:///{(tmp_path / 'identity.db').as_posix()}",
        "ASTRIA_SIGNING_KEY_PATH": str(tmp_path / "signing.pem"),
        "ASTRIA_ARGON2_MEMORY_KIB": "64",
        "ASTRIA_ARGON2_TIME_COST": "1",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


def test_bootstrap_admin_then_login(cli_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    password = "Cli-Password-Uji-9731"
    monkeypatch.setenv("IDENTITY_BOOTSTRAP_PASSWORD", password)
    assert cli.main(["bootstrap-admin", "--username", "root.admin", "--display-name", "Root"]) == 0
    assert password not in capsys.readouterr().out
    # Admin kedua ditolak tanpa --force.
    assert cli.main(["bootstrap-admin", "--username", "admin.dua"]) == 1
    assert cli.main(["bootstrap-admin", "--username", "admin.dua", "--force"]) == 0

    settings = Settings()
    with TestClient(build_app(settings)) as client:
        from astria_common.auth import issue_service_token

        token, _ = issue_service_token(
            client.app.state.identity.keys.signing, subject="svc:api", audience="svc:identity", act=None, ttl=60
        )
        resp = client.post(
            "/internal/v1/auth/login",
            json={"username": "root.admin", "password": password},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["user"]["roles"] == ["admin"]


def test_bootstrap_admin_rejects_weak_password(cli_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDENTITY_BOOTSTRAP_PASSWORD", "pendek")
    assert cli.main(["bootstrap-admin", "--username", "root.admin"]) == 1


def test_rotate_signing_key_via_cli(cli_env: dict[str, str], capsys) -> None:
    assert cli.main(["rotate-signing-key"]) == 0
    out = capsys.readouterr().out
    assert "idn-" in out
    settings = Settings()
    with TestClient(build_app(settings)) as client:
        kids = {k["kid"] for k in client.get("/internal/v1/keys").json()["keys"]}
    assert len(kids) == 2  # kunci baru (aktif) dan kunci lama (overlap)


def test_verify_config(cli_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    assert cli.main(["verify-config"]) == 0
    monkeypatch.delenv("ASTRIA_DATABASE_URL")
    assert cli.main(["verify-config"]) == 1
    assert "ASTRIA_DATABASE_URL" in capsys.readouterr().err
