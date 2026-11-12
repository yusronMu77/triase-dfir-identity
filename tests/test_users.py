"""Akun, peran, otorisasi admin + re-autentikasi, dan audit sinkron fail-closed."""

import secrets

import pytest
from astria_contracts.events.audit_record import AuditRecord
from conftest import ADMIN_ID, ANALIS_ID, Env, outbox_rows


def new_user_body(**over: object) -> dict[str, object]:
    return {
        "username": "budi.dfir",
        "display_name": "Budi",
        "password": secrets.token_urlsafe(18),
        "roles": ["dfir"],
    } | over


def test_create_user_needs_admin_with_fresh_reauth(env: Env) -> None:
    body = new_user_body()
    assert env.call("POST", "/users", body).status_code == 403  # tanpa act
    analis = env.session("analis1")
    denied = env.call("POST", "/users", body, act=analis["act"])
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "PERAN_TIDAK_CUKUP"

    admin = env.session("admin1")  # login saja, belum reauth
    needs = env.call("POST", "/users", body, act=admin["act"])
    assert needs.status_code == 403 and needs.json()["error"]["code"] == "REAUTH_DIPERLUKAN"

    admin = env.session("admin1", reauth=True)
    created = env.call("POST", "/users", body, act=admin["act"])
    assert created.status_code == 201, created.text
    user = created.json()
    assert user["roles"] == ["dfir"] and user["active"] is True
    assert env.login("budi.dfir", body["password"]).status_code == 200  # type: ignore[arg-type]


def test_reauth_window_expires(env: Env) -> None:
    from datetime import timedelta

    admin = env.session("admin1", reauth=True)
    env.clock.advance(timedelta(minutes=env.settings.reauth_window_minutes + 1))
    resp = env.call("POST", "/users", new_user_body(), act=admin["act"])
    assert resp.status_code == 403 and resp.json()["error"]["code"] == "REAUTH_DIPERLUKAN"


def test_admin_role_comes_from_database_not_from_claim(env: Env) -> None:
    analis = env.session("analis1", reauth=True)
    forged = analis["act"] | {"roles": ["admin"]}  # klaim palsu: peran dibaca dari DB
    resp = env.call("POST", "/users", new_user_body(), act=forged)
    assert resp.status_code == 403 and resp.json()["error"]["code"] == "PERAN_TIDAK_CUKUP"


def test_duplicate_username_and_policy(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    dup = env.call("POST", "/users", new_user_body(username="ANALIS1"), act=admin["act"])
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "USERNAME_SUDAH_ADA"
    weak = env.call("POST", "/users", new_user_body(password="aaaaaaaaaaaaaaaa"), act=admin["act"])
    assert weak.status_code == 422 and weak.json()["error"]["code"] == "KEBIJAKAN_KATA_SANDI"
    unknown_role = env.call("POST", "/users", new_user_body(roles=["juri"]), act=admin["act"])
    assert unknown_role.status_code == 400


def test_list_get_and_pagination(env: Env) -> None:
    admin = env.session("admin1")
    page = env.call("GET", "/users?limit=1", act=admin["act"]).json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    rest = env.call("GET", f"/users?limit=10&cursor={page['next_cursor']}", act=admin["act"]).json()
    assert [u["user_id"] for u in page["items"] + rest["items"]] == [ADMIN_ID, ANALIS_ID]
    assert rest["next_cursor"] is None
    assert env.call("GET", f"/users/{ANALIS_ID}").json()["username"] == "analis1"
    assert env.call("GET", "/users/usr_TIDAKADA").status_code == 404
    assert "password" not in str(env.call("GET", f"/users/{ANALIS_ID}").json()).lower()


def test_cannot_remove_last_admin(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    demote = env.call("PUT", f"/users/{ADMIN_ID}/roles", {"roles": ["analis"]}, act=admin["act"])
    assert demote.status_code == 422 and demote.json()["error"]["code"] == "ADMIN_TERAKHIR", demote.text
    disable = env.call("PATCH", f"/users/{ADMIN_ID}", {"active": False}, act=admin["act"])
    assert disable.status_code == 422, disable.text  # tidak boleh menonaktifkan diri sendiri


def test_password_change_revokes_sessions_and_emits_event(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    analis = env.session("analis1")
    new_pw = secrets.token_urlsafe(18)
    resp = env.call("PATCH", f"/users/{ANALIS_ID}", {"password": new_pw}, act=admin["act"])
    assert resp.status_code == 200, resp.text
    assert env.call("POST", "/sessions/introspect", {"token": analis["token"]}).json() == {"active": False}
    assert env.login("analis1").status_code == 401
    assert env.login("analis1", new_pw).status_code == 200
    assert outbox_rows(env, "identity.revoked")


def test_revoke_all_sessions_admin_or_owner_only(env: Env) -> None:
    analis = env.session("analis1")
    other = env.session("analis1")
    resp = env.call("DELETE", f"/users/{ANALIS_ID}/sessions", act=analis["act"])  # pemilik sendiri
    assert resp.status_code == 204
    assert env.call("POST", "/sessions/introspect", {"token": other["token"]}).json()["active"] is False
    admin = env.session("admin1")
    assert env.call("DELETE", f"/users/{ADMIN_ID}/sessions", act=env.session("analis1")["act"]).status_code == 403
    assert env.call("DELETE", f"/users/{ANALIS_ID}/sessions", act=admin["act"]).status_code == 403  # perlu reauth


def test_sync_audit_failure_rolls_back_user_creation(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    env.audit.fail = True
    body = new_user_body()
    resp = env.call("POST", "/users", body, act=admin["act"])
    assert resp.status_code == 503, resp.text
    env.audit.fail = False
    assert env.login(body["username"], body["password"]).status_code == 401  # type: ignore[arg-type]
    page = env.call("GET", "/users", act=env.session("admin1")["act"]).json()
    assert [u["username"] for u in page["items"]] == ["admin1", "analis1"]


def test_sync_audit_failure_blocks_role_change(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    env.audit.fail = True
    resp = env.call("PUT", f"/users/{ANALIS_ID}/roles", {"roles": ["dfir"]}, act=admin["act"])
    assert resp.status_code == 503
    env.audit.fail = False
    assert env.call("GET", f"/users/{ANALIS_ID}").json()["roles"] == ["analis"]


def test_audit_records_are_contract_valid_and_secret_free(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    body = new_user_body()
    env.call("POST", "/users", body, act=admin["act"])
    env.call("PUT", f"/users/{ANALIS_ID}/roles", {"roles": ["dfir", "analis"]}, act=admin["act"])
    assert env.audit.actions() == ["identity.user.created", "identity.role.changed"]
    for record in env.audit.records:
        AuditRecord.model_validate(record.model_dump(mode="json"))
        assert body["password"] not in record.model_dump_json()
    for row in outbox_rows(env):
        assert body["password"] not in str(row["envelope"])


@pytest.mark.parametrize("path", ["/users", f"/users/{ANALIS_ID}"])
def test_users_endpoints_reject_non_api_callers(env: Env, path: str) -> None:
    assert env.call("GET", path, caller="ingest").status_code == 403
