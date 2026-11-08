import json
from pathlib import Path

import orjson
import pytest
from astria_common.auth import JwksSource, ServiceTokenVerifier
from astria_common.hmac_auth import signed_headers
from fastapi.testclient import TestClient

from astria_identity.main import build_app
from astria_identity.settings import Settings

INGEST_KEY = bytes(range(32))
API_KEY = bytes(range(32, 64))
PATH = "/internal/v1/service-tokens"


@pytest.fixture
def client(tmp_path: Path):
    keys = tmp_path / "service-keys.json"
    keys.write_text(json.dumps({"ingest": INGEST_KEY.hex(), "api": API_KEY.hex()}), encoding="utf-8")
    settings = Settings(env="test", signing_key_path=tmp_path / "signing.pem", service_keys_file=keys)
    with TestClient(build_app(settings)) as c:
        yield c


def request_token(client: TestClient, service: str, key: bytes, body: dict):
    raw = orjson.dumps(body)
    headers = signed_headers(service, key, "POST", PATH, raw) | {"Content-Type": "application/json"}
    return client.post(PATH, content=raw, headers=headers)


@pytest.mark.anyio
async def test_token_roundtrip_verifies_with_published_keys(client: TestClient) -> None:
    resp = request_token(client, "ingest", INGEST_KEY, {"audience": "svc:audit"})
    assert resp.status_code == 201, resp.text
    token = resp.json()["token"]

    jwks = client.get("/internal/v1/keys").json()
    assert jwks["keys"][0]["alg"] == "EdDSA"
    verifier = ServiceTokenVerifier(JwksSource("http://unused", fetch=lambda: jwks))
    principal = await verifier.verify(token, "svc:audit")
    assert principal.subject == "svc:ingest"
    assert principal.act is None


def test_wrong_key_is_401(client: TestClient) -> None:
    resp = request_token(client, "ingest", API_KEY, {"audience": "svc:audit"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "HMAC_TIDAK_VALID"


def test_unknown_service_is_401(client: TestClient) -> None:
    assert request_token(client, "rogue", INGEST_KEY, {"audience": "svc:audit"}).status_code == 401


def test_replay_is_401(client: TestClient) -> None:
    raw = orjson.dumps({"audience": "svc:audit"})
    headers = signed_headers("ingest", INGEST_KEY, "POST", PATH, raw)
    assert client.post(PATH, content=raw, headers=headers).status_code == 201
    assert client.post(PATH, content=raw, headers=headers).status_code == 401


def test_act_only_from_api(client: TestClient) -> None:
    act = {"sub": "usr_01ABC", "roles": ["analis"]}
    assert request_token(client, "ingest", INGEST_KEY, {"audience": "svc:audit", "act": act}).status_code == 403
    assert request_token(client, "api", API_KEY, {"audience": "svc:audit", "act": act}).status_code == 201


def test_self_audience_is_403(client: TestClient) -> None:
    assert request_token(client, "ingest", INGEST_KEY, {"audience": "svc:ingest"}).status_code == 403


def test_ready_reports_keys(client: TestClient) -> None:
    body = client.get("/ready").json()
    assert body["checks"]["keys"]["status"] == "ok"
