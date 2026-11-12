"""Login, sesi, introspeksi, re-autentikasi, throttle, dan pemanggil yang sah."""

from datetime import timedelta

from conftest import Env, outbox_rows


def test_ready_after_bootstrap(env: Env) -> None:
    body = env.client.get("/ready").json()
    assert body["status"] == "ok", body
    assert {"keys", "bootstrap"} <= set(body["checks"])


def test_login_introspect_logout(env: Env) -> None:
    resp = env.login("analis1")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["session_token"]) == 43
    assert data["user"] == {"user_id": "usr_ANALISAAAAAA", "username": "analis1", "roles": ["analis"]}

    info = env.call("POST", "/sessions/introspect", {"token": data["session_token"]}).json()
    assert info["active"] is True
    assert info["roles"] == ["analis"]
    assert info["session_id"].startswith("ses_")

    assert env.call("POST", "/auth/logout", {"token": data["session_token"]}).status_code == 204
    assert env.call("POST", "/sessions/introspect", {"token": data["session_token"]}).json() == {"active": False}
    assert env.call("POST", "/auth/logout", {"token": data["session_token"]}).status_code == 401


def test_login_is_case_insensitive_on_username(env: Env) -> None:
    assert env.login("ANALIS1", env.passwords["analis1"]).status_code == 200


def test_wrong_password_and_unknown_user_look_identical(env: Env) -> None:
    wrong = env.login("analis1", "salah-salah-salah-1")
    unknown = env.login("tidak-ada", "salah-salah-salah-1")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error"]["code"] == unknown.json()["error"]["code"] == "KREDENSIAL_TIDAK_VALID"
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]


def test_session_expires_idle_and_absolute(env: Env) -> None:
    token = env.login("analis1").json()["session_token"]
    env.clock.advance(timedelta(minutes=env.settings.session_idle_minutes + 1))
    assert env.call("POST", "/sessions/introspect", {"token": token}).json()["active"] is False

    token = env.login("analis1").json()["session_token"]
    for _ in range(env.settings.session_max_hours * 2 + 1):  # tetap aktif tiap 29 menit, tapi batas mutlak berlaku
        env.clock.advance(timedelta(minutes=29))
        if not env.call("POST", "/sessions/introspect", {"token": token}).json()["active"]:
            break
    else:
        raise AssertionError("sesi harus berhenti di batas mutlak")


def test_role_change_applies_on_next_introspection(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    analis = env.session("analis1")
    resp = env.call("PUT", f"/users/{analis['user_id']}/roles", {"roles": ["dfir"]}, act=admin["act"])
    assert resp.status_code == 200, resp.text
    # Perubahan peran mencabut sesi lama; login baru membawa peran baru.
    assert env.call("POST", "/sessions/introspect", {"token": analis["token"]}).json() == {"active": False}
    assert env.session("analis1")["act"]["roles"] == ["dfir"]
    revoked = outbox_rows(env, "identity.revoked")
    assert revoked and revoked[-1]["envelope"]["data"]["reason"] == "peran_berubah"


def test_login_throttle_per_user_returns_429_with_retry_after(env: Env) -> None:
    for _ in range(env.settings.login_fail_limit_user):
        assert env.login("analis1", "salah-salah-salah-1").status_code == 401
    blocked = env.login("analis1")  # kata sandi benar pun ditolak selama diblokir
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1
    assert blocked.json()["error"]["code"] == "TERLALU_BANYAK_PERCOBAAN"
    env.clock.advance(timedelta(minutes=env.settings.login_fail_window_minutes + 1))
    assert env.login("analis1").status_code == 200


def test_login_throttle_per_ip(env: Env) -> None:
    ip = "a" * 64
    for i in range(env.settings.login_fail_limit_ip):
        assert env.login(f"orang{i}", "salah-salah-salah-1", ip_hash=ip).status_code == 401
    assert env.login("analis1", ip_hash=ip).status_code == 429
    assert env.login("analis1", ip_hash="b" * 64).status_code == 200


def test_reauth_sets_window_and_rejects_wrong_password(env: Env) -> None:
    token = env.login("admin1").json()["session_token"]
    bad = env.call("POST", "/auth/reauth", {"token": token, "password": "salah-salah-salah-1"})
    assert bad.status_code == 401
    ok = env.call("POST", "/auth/reauth", {"token": token, "password": env.passwords["admin1"]})
    assert ok.status_code == 200
    assert env.call("POST", "/sessions/introspect", {"token": token}).json()["reauth_at"]


def test_disabled_account_cannot_login(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    resp = env.call("PATCH", "/users/usr_ANALISAAAAAA", {"active": False}, act=admin["act"])
    assert resp.status_code == 200, resp.text
    assert env.login("analis1").status_code == 401


def test_endpoints_require_service_token_from_api_only(env: Env) -> None:
    body = {"username": "analis1", "password": env.passwords["analis1"]}
    assert env.call("POST", "/auth/login", body, authed=False).status_code == 401
    assert env.call("POST", "/auth/login", body, caller="ingest").status_code == 403
    wrong_aud = env.client.post(
        "/internal/v1/auth/login",
        json=body,
        headers={"Authorization": f"Bearer {env.token(audience='svc:audit')}"},
    )
    assert wrong_aud.status_code == 403
    assert wrong_aud.json()["error"]["code"] == "AUDIENS_SALAH"
