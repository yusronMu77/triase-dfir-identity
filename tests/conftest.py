"""Fixture bersama: aplikasi identity di SQLite sementara, sink audit palsu, dan pembantu pemanggil `svc:api`."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from astria_common.auth import issue_service_token
from fastapi.testclient import TestClient
from pydantic import SecretStr

from astria_identity.clock import Clock
from astria_identity.events import AuditSink
from astria_identity.main import build_app
from astria_identity.settings import Settings

ADMIN_ID = "usr_ADMINAAAAAAA"
ANALIS_ID = "usr_ANALISAAAAAA"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean_astria_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uji tidak boleh membaca ASTRIA_* milik kontainer dev."""
    for key in list(os.environ):
        if key.startswith("ASTRIA_") and not key.startswith("ASTRIA_TEST_"):
            monkeypatch.delenv(key, raising=False)


class FakeAudit(AuditSink):
    """Sink audit sinkron untuk uji; `fail=True` meniru layanan audit yang mati."""

    def __init__(self) -> None:
        self.records: list[Any] = []
        self.fail = False

    async def record(self, record: Any) -> None:
        if self.fail:
            from astria_common.audit_client import AuditUnavailable

            raise AuditUnavailable("tidak tersedia")
        self.records.append(record)

    def actions(self) -> list[str]:
        return [r.action for r in self.records]


@dataclass
class Env:
    client: TestClient
    app: Any
    audit: FakeAudit
    clock: Clock
    settings: Settings
    passwords: dict[str, str] = field(default_factory=dict)
    service_keys: dict[str, bytes] = field(default_factory=dict)

    @property
    def ident(self) -> Any:
        return self.app.state.identity

    def token(self, *, caller: str = "api", audience: str = "svc:identity", act: dict[str, Any] | None = None) -> str:
        token, _ = issue_service_token(
            self.ident.keys.signing, subject=f"svc:{caller}", audience=audience, act=act, ttl=120
        )
        return token

    def call(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        act: dict[str, Any] | None = None,
        caller: str = "api",
        authed: bool = True,
    ):
        headers = {"Authorization": f"Bearer {self.token(caller=caller, act=act)}"} if authed else {}
        return self.client.request(method, f"/internal/v1{path}", json=body, headers=headers)

    def service_token(self, service: str, body: dict[str, Any], key: bytes | None = None):
        """Minta token layanan lewat jalur HMAC (tanpa bearer)."""
        import orjson
        from astria_common.hmac_auth import signed_headers

        path = "/internal/v1/service-tokens"
        raw = orjson.dumps(body)
        headers = signed_headers(service, key or self.service_keys[service], "POST", path, raw)
        return self.client.post(path, content=raw, headers=headers | {"Content-Type": "application/json"})

    def login(self, username: str, password: str | None = None, *, ip_hash: str | None = None):
        body: dict[str, Any] = {"username": username, "password": password or self.passwords[username]}
        if ip_hash:
            body["client"] = {"ip_hash": ip_hash}
        return self.call("POST", "/auth/login", body)

    def session(self, username: str, *, reauth: bool = False) -> dict[str, Any]:
        """Login (dan reauth bila diminta); kembalikan token sesi dan klaim `act` untuk api."""
        resp = self.login(username)
        assert resp.status_code == 200, resp.text
        token = resp.json()["session_token"]
        if reauth:
            ok = self.call("POST", "/auth/reauth", {"token": token, "password": self.passwords[username]})
            assert ok.status_code == 200, ok.text
        info = self.call("POST", "/sessions/introspect", {"token": token}).json()
        act = {"sub": info["user_id"], "roles": info["roles"], "session_id": info["session_id"]}
        return {"token": token, "act": act, "user_id": info["user_id"]}


def make_env(tmp_path: Path, *, extra_users: list[dict[str, Any]] | None = None, **overrides: Any) -> Env:
    pw = {"admin1": secrets.token_urlsafe(18), "analis1": secrets.token_urlsafe(18)}
    seed = [
        {"user_id": ADMIN_ID, "username": "admin1", "password": pw["admin1"], "roles": ["admin"]},
        {"user_id": ANALIS_ID, "username": "analis1", "password": pw["analis1"], "roles": ["analis"]},
        *(extra_users or []),
    ]
    seed_file = tmp_path / "seed-users.json"
    seed_file.write_text(json.dumps(seed), encoding="utf-8")
    service_keys = {name: secrets.token_bytes(32) for name in ("api", "ingest", "gateway", "devtools")}
    keys_file = tmp_path / "service-keys.json"
    keys_file.write_text(json.dumps({n: k.hex() for n, k in service_keys.items()}), encoding="utf-8")
    values: dict[str, Any] = {
        "service_keys_file": keys_file,
        "env": "test",
        "database_url": SecretStr(f"sqlite+aiosqlite:///{(tmp_path / 'identity.db').as_posix()}"),
        "signing_key_path": tmp_path / "signing.pem",
        "seed_users_file": seed_file,
        "argon2_memory_kib": 64,
        "argon2_time_cost": 1,
    }
    values.update(overrides)
    settings = Settings(**values)
    audit, clock = FakeAudit(), Clock()
    app = build_app(settings, audit=audit, clock=clock)
    client = TestClient(app)
    client.__enter__()
    return Env(
        client=client, app=app, audit=audit, clock=clock, settings=settings, passwords=pw, service_keys=service_keys
    )


def reopen(previous: Env) -> Env:
    """Mulai ulang layanan di atas basis data, kunci, dan berkas yang sama (uji idempotensi bootstrap)."""
    audit, clock = FakeAudit(), Clock()
    app = build_app(previous.settings, audit=audit, clock=clock)
    client = TestClient(app)
    client.__enter__()
    return Env(
        client=client,
        app=app,
        audit=audit,
        clock=clock,
        settings=previous.settings,
        passwords=previous.passwords,
        service_keys=previous.service_keys,
    )


@pytest.fixture
def env(tmp_path: Path):
    e = make_env(tmp_path)
    yield e
    e.client.__exit__(None, None, None)


def outbox_rows(e: Env, event_type: str | None = None) -> list[dict[str, Any]]:
    """Event di tabel outbox (ditulis satu transaksi dengan perubahan datanya); `envelope` berupa dict."""
    from astria_common import outbox
    from sqlalchemy import select

    async def go() -> list[dict[str, Any]]:
        async with e.ident.engine.connect() as conn:
            rows = (await conn.execute(select(outbox.outbox).order_by(outbox.outbox.c.created_at))).all()
        return [dict(r._mapping) for r in rows]

    # Mesin hidup di loop milik TestClient; jalankan lewat portalnya.
    rows = e.client.portal.call(go)
    for row in rows:
        if isinstance(row["envelope"], str):
            row["envelope"] = json.loads(row["envelope"])
    return [r for r in rows if event_type is None or r["event_type"] == event_type]
