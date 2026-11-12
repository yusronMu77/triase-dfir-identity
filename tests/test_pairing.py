"""Kode pairing: terbit, klaim sekali pakai, kedaluwarsa, throttle klaim, tanpa kode mentah di basis data."""

import hashlib
from datetime import timedelta

from conftest import ANALIS_ID, Env, outbox_rows
from sqlalchemy import select

from astria_identity.tables import pairing_codes

EXT = hashlib.sha256(b"whatsapp:6281200000001").hexdigest()


def issue(env: Env, channel: str | None = "whatsapp") -> dict:
    analis = env.session("analis1")
    resp = env.call("POST", "/pairing-codes", {"channel": channel} if channel else None, act=analis["act"])
    assert resp.status_code == 201, resp.text
    return resp.json()


def claim(env: Env, code: str, ext: str = EXT, channel: str = "whatsapp"):
    return env.call("POST", "/pairing/claim", {"channel": channel, "external_id_hash": ext, "code": code})


def test_issue_and_claim_once(env: Env) -> None:
    issued = issue(env)
    assert len(issued["code"]) == 8 and issued["channel"] == "whatsapp"
    ok = claim(env, issued["code"].lower())  # huruf kecil diterima
    assert ok.status_code == 200, ok.text
    assert ok.json()["user_id"] == ANALIS_ID
    assert claim(env, issued["code"]).status_code == 409


def test_issue_requires_logged_in_user(env: Env) -> None:
    assert env.call("POST", "/pairing-codes", None).status_code == 403


def test_unknown_code_expired_and_wrong_channel(env: Env) -> None:
    assert claim(env, "ZZZZZZZZ").status_code == 401
    issued = issue(env)
    assert claim(env, issued["code"], channel="telegram").status_code in {401, 409}
    env.clock.advance(timedelta(minutes=env.settings.pairing_ttl_minutes + 1))
    assert claim(env, issued["code"]).status_code == 410


def test_claim_throttle_per_external_identity(env: Env) -> None:
    for _ in range(env.settings.pairing_claim_limit):
        assert claim(env, "ZZZZZZZZ").status_code == 401
    blocked = claim(env, issue(env)["code"])
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) >= 1
    assert claim(env, issue(env)["code"], ext="f" * 64).status_code == 200  # identitas lain tidak terdampak


def test_only_hash_is_stored(env: Env) -> None:
    issued = issue(env)

    async def rows() -> list:
        async with env.ident.engine.connect() as conn:
            return (await conn.execute(select(pairing_codes))).all()

    stored = env.client.portal.call(rows)
    assert len(stored) == 1
    assert issued["code"] not in repr(stored)
    assert claim(env, issued["code"]).status_code == 200
    audit = [r["envelope"] for r in outbox_rows(env, "audit.record")]
    assert all(issued["code"] not in str(a) for a in audit)
    assert any(a["data"]["action"] == "identity.pairing.claimed" for a in audit)
