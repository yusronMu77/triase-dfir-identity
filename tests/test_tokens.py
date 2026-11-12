"""Token layanan: HMAC, matriks audiens, klaim act, JWKS, rotasi kunci, serangan JWT."""

import base64
import json
import time
from datetime import timedelta

import jwt
import orjson
import pytest
from astria_common.auth import JwksSource, ServiceTokenVerifier
from astria_common.hmac_auth import signed_headers
from conftest import ANALIS_ID, Env, outbox_rows

PATH = "/internal/v1/service-tokens"


async def verify(env: Env, token: str, audience: str):
    jwks = env.client.get("/internal/v1/keys").json()
    return await ServiceTokenVerifier(JwksSource("http://unused", fetch=lambda: jwks)).verify(token, audience)


@pytest.mark.anyio
async def test_roundtrip_ttl_and_claims(env: Env) -> None:
    resp = env.service_token("ingest", {"audience": "svc:audit"})
    assert resp.status_code == 201, resp.text
    principal = await verify(env, resp.json()["token"], "svc:audit")
    assert principal.subject == "svc:ingest" and principal.act is None
    assert principal.claims["exp"] - principal.claims["iat"] == env.settings.token_ttl_seconds


def test_wrong_key_unknown_service_and_replay_are_401(env: Env) -> None:
    assert env.service_token("ingest", {"audience": "svc:audit"}, key=env.service_keys["api"]).status_code == 401
    assert env.service_token("rogue", {"audience": "svc:audit"}, key=bytes(32)).status_code == 401
    raw = orjson.dumps({"audience": "svc:audit"})
    headers = signed_headers("ingest", env.service_keys["ingest"], "POST", PATH, raw)
    assert env.client.post(PATH, content=raw, headers=headers).status_code == 201
    assert env.client.post(PATH, content=raw, headers=headers).status_code == 401


def test_stale_timestamp_is_401(env: Env) -> None:
    raw = orjson.dumps({"audience": "svc:audit"})
    headers = signed_headers("ingest", env.service_keys["ingest"], "POST", PATH, raw, now=time.time() - 3600)
    assert env.client.post(PATH, content=raw, headers=headers).status_code == 401


@pytest.mark.parametrize(
    ("service", "audience", "status"),
    [
        ("api", "svc:config", 201),  # api boleh ke semua audiens
        ("ingest", "svc:audit", 201),
        ("ingest", "svc:config", 403),  # di luar matriks
        ("ingest", "svc:ingest", 403),  # diri sendiri
        ("devtools", "svc:ticket", 201),
    ],
)
def test_audience_matrix(env: Env, service: str, audience: str, status: int) -> None:
    assert env.service_token(service, {"audience": audience}).status_code == status


def test_denied_audience_is_audited_without_blocking(env: Env) -> None:
    assert env.service_token("ingest", {"audience": "svc:config"}).status_code == 403
    rows = outbox_rows(env, "audit.record")
    assert any(r["envelope"]["data"]["action"] == "identity.token.denied" for r in rows)


def test_act_only_from_api_and_must_be_known_active_user(env: Env) -> None:
    act = {"sub": ANALIS_ID, "roles": ["admin"]}  # klaim peran dibohongi
    assert env.service_token("ingest", {"audience": "svc:audit", "act": act}).status_code == 403
    ghost = {"sub": "usr_TIDAKADA", "roles": ["analis"]}
    assert env.service_token("api", {"audience": "svc:audit", "act": ghost}).status_code == 403
    ok = env.service_token("api", {"audience": "svc:audit", "act": act})
    assert ok.status_code == 201, ok.text
    claims = jwt.decode(ok.json()["token"], options={"verify_signature": False})
    assert claims["act"]["roles"] == ["analis"]  # ditimpa dari basis data


def test_act_with_revoked_session_is_denied(env: Env) -> None:
    analis = env.session("analis1")
    env.call("POST", "/auth/logout", {"token": analis["token"]})
    denied = env.service_token("api", {"audience": "svc:audit", "act": analis["act"]})
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "ACT_DITOLAK"


def test_invalid_body_is_400(env: Env) -> None:
    assert env.service_token("api", {"audience": "audit"}).status_code == 400
    assert env.service_token("api", {}).status_code == 400


def test_jwks_has_only_public_material(env: Env) -> None:
    body = env.client.get("/internal/v1/keys").json()
    assert body["keys"]
    assert all(set(k) <= {"kty", "crv", "x", "kid", "alg", "use"} for k in body["keys"])


def _enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_forged_tokens_are_rejected(env: Env) -> None:
    now = int(time.time())
    key = env.ident.keys.signing
    claims = {"iss": "astria-identity", "sub": "svc:api", "aud": "svc:identity", "iat": now, "exp": now + 100}
    body = {"username": "analis1", "password": env.passwords["analis1"]}

    def post(token: str):
        return env.client.post("/internal/v1/auth/login", json=body, headers={"Authorization": f"Bearer {token}"})

    for header in ({"alg": "none", "typ": "JWT"}, {"alg": "HS256", "typ": "JWT", "kid": key.kid}):
        forged = f"{_enc(json.dumps(header).encode())}.{_enc(json.dumps(claims).encode())}.{_enc(b'x' * 32)}"
        assert post(forged).status_code == 401, header
    expired = jwt.encode(
        dict(claims, iat=now - 1000, exp=now - 500), key.private_key, algorithm="EdDSA", headers={"kid": key.kid}
    )
    assert post(expired).status_code == 401
    assert post(env.token()).status_code == 200  # token yang sah tetap diterima


def test_service_key_rotation_overlap_then_retire(env: Env) -> None:
    admin = env.session("admin1", reauth=True)
    old_key = env.service_keys["ingest"]
    resp = env.call("POST", "/service-keys/ingest/rotate", act=admin["act"])
    assert resp.status_code == 201, resp.text
    data = resp.json()
    new_key = bytes.fromhex(data["key"])
    assert data["service"] == "ingest" and data["previous_key_id"] and data["key_id"] != data["previous_key_id"]
    # Selama overlap kedua kunci sah; sesudahnya hanya yang baru.
    assert env.service_token("ingest", {"audience": "svc:audit"}, key=new_key).status_code == 201
    assert env.service_token("ingest", {"audience": "svc:audit"}, key=old_key).status_code == 201
    env.clock.advance(timedelta(hours=env.settings.key_overlap_hours + 1))
    assert env.service_token("ingest", {"audience": "svc:audit"}, key=old_key).status_code == 401
    assert env.service_token("ingest", {"audience": "svc:audit"}, key=new_key).status_code == 201
    assert "identity.key.rotated" in env.audit.actions()
    assert data["key"] not in "".join(r.model_dump_json() for r in env.audit.records)


def test_rotation_needs_admin_reauth_unknown_service_404_and_audit_fail_closed(env: Env) -> None:
    analis = env.session("analis1", reauth=True)
    assert env.call("POST", "/service-keys/ingest/rotate", act=analis["act"]).status_code == 403
    admin = env.session("admin1", reauth=True)
    assert env.call("POST", "/service-keys/tidak-ada/rotate", act=admin["act"]).status_code == 404
    env.audit.fail = True
    assert env.call("POST", "/service-keys/ingest/rotate", act=admin["act"]).status_code == 503
    env.audit.fail = False
    # Rotasi yang gagal tidak mengubah apa pun: kunci lama tetap satu-satunya yang aktif.
    assert env.service_token("ingest", {"audience": "svc:audit"}).status_code == 201


def test_signing_key_rotation_keeps_old_tokens_valid_during_overlap(env: Env) -> None:
    from astria_identity.janitor import reload_signing_key
    from astria_identity.keys import register_signing_key, write_new_signing_key

    old_kid = env.ident.keys.signing.kid

    async def rotate() -> str:
        async with env.ident.engine.begin() as conn:
            await register_signing_key(conn, env.ident.keys.signing, env.clock.now(), env.ident.overlap)
        new = write_new_signing_key(env.settings.signing_key_path)
        env.ident.keys._signing_mtime = 0.0  # noqa: SLF001 - paksa deteksi berkas baru (mtime bisa sama)
        await reload_signing_key(env.ident)
        return new.kid

    new_kid = env.client.portal.call(rotate)
    assert env.ident.keys.signing.kid == new_kid
    assert {k["kid"] for k in env.client.get("/internal/v1/keys").json()["keys"]} == {old_kid, new_kid}
    token = env.service_token("ingest", {"audience": "svc:audit"}).json()["token"]
    assert jwt.get_unverified_header(token)["kid"] == new_kid
    env.clock.advance(timedelta(hours=env.settings.key_overlap_hours + 1))
    assert {k["kid"] for k in env.client.get("/internal/v1/keys").json()["keys"]} == {new_kid}
