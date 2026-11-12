"""Keamanan: tidak ada rahasia di log atau respons, tidak ada enumerasi akun, validasi masukan."""

import json
import secrets

import pytest
from conftest import ANALIS_ID, Env


def test_logs_never_contain_secrets(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    new_password = secrets.token_urlsafe(18)
    env.login("analis1", "salah-salah-salah-1")
    session = env.session("analis1")
    admin = env.session("admin1", reauth=True)
    env.call(
        "POST",
        "/users",
        {"username": "log.cek", "display_name": "Log", "password": new_password, "roles": ["analis"]},
        act=admin["act"],
    )
    rotated = env.call("POST", "/service-keys/ingest/rotate", act=admin["act"]).json()
    env.service_token("ingest", {"audience": "svc:audit"})
    output = capsys.readouterr().out
    assert output  # ada log
    secrets_seen = [
        env.passwords["analis1"],
        env.passwords["admin1"],
        new_password,
        session["token"],
        admin["token"],
        rotated["key"],
        *(k.hex() for k in env.service_keys.values()),
        "salah-salah-salah-1",
        "Bearer ",
    ]
    for secret in secrets_seen:
        assert secret not in output, f"rahasia bocor di log: {secret[:4]}…"


def test_responses_never_expose_password_material(env: Env) -> None:
    admin = env.session("admin1")
    body = json.dumps(env.call("GET", "/users", act=admin["act"]).json()).lower()
    for marker in ("argon2", "password", "token_hash", "secret"):
        assert marker not in body


def test_no_account_enumeration_on_login_and_reauth(env: Env) -> None:
    real = env.login("analis1", "salah-salah-salah-1")
    fake = env.login("hantu", "salah-salah-salah-1")
    assert (real.status_code, real.json()["error"]["code"]) == (fake.status_code, fake.json()["error"]["code"])
    assert real.json()["error"]["message"] == fake.json()["error"]["message"]
    # Akun nonaktif terlihat sama dengan kata sandi salah.
    admin = env.session("admin1", reauth=True)
    env.call("PATCH", f"/users/{ANALIS_ID}", {"active": False}, act=admin["act"])
    disabled = env.login("analis1")
    assert (disabled.status_code, disabled.json()["error"]["message"]) == (401, real.json()["error"]["message"])


def test_unknown_fields_and_bad_shapes_are_400(env: Env) -> None:
    assert env.call("POST", "/auth/login", {"username": "a", "password": "b", "extra": 1}).status_code == 400
    assert env.call("POST", "/auth/login", {"username": "", "password": "b"}).status_code == 400
    assert env.call("POST", "/sessions/introspect", {}).status_code == 400
    assert env.call("GET", "/users/bukan-id").status_code == 400
    assert (
        env.call("POST", "/pairing/claim", {"channel": "wa", "external_id_hash": "xyz", "code": "ABCDEFGH"}).status_code
        == 400
    )


def test_session_token_is_opaque_and_unique(env: Env) -> None:
    tokens = {env.login("analis1").json()["session_token"] for _ in range(5)}
    assert len(tokens) == 5
    assert all(len(t) == 43 and "." not in t for t in tokens)


def test_error_bodies_follow_standard_shape(env: Env) -> None:
    resp = env.login("analis1", "salah-salah-salah-1")
    assert set(resp.json()) == {"error"}
    assert set(resp.json()["error"]) == {"code", "message", "trace_id"}
