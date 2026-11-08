"""API internal identity Tahap 0 (kontrak: contracts/openapi/identity-internal.yaml)."""

from __future__ import annotations

from astria_common.auth import issue_service_token
from astria_common.errors import AstriaError
from astria_common.hmac_auth import H_SERVICE, HmacError, verify
from astria_common.log import get_logger
from astria_contracts.openapi.identity_internal import Jwks, ServiceTokenRequest, ServiceTokenResponse
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from astria_identity.keys import KeyStore

log = get_logger(__name__)
router = APIRouter(prefix="/internal/v1", tags=["identity"])


def _store(request: Request) -> KeyStore:
    return request.app.state.components["keys"]


@router.get("/keys", response_model=Jwks)
async def public_keys(request: Request) -> Jwks:
    store = _store(request)
    if store.signing is None:
        raise AstriaError("KUNCI_TIDAK_TERSEDIA", "kunci penandatanganan tidak tersedia", 503)
    return Jwks.model_validate({"keys": [store.signing.public_jwk()]})


@router.post("/service-tokens", status_code=201, response_model=ServiceTokenResponse)
async def service_token(request: Request) -> JSONResponse:
    store = _store(request)
    if store.signing is None:
        raise AstriaError("KUNCI_TIDAK_TERSEDIA", "kunci penandatanganan tidak tersedia", 503)

    service = request.headers.get(H_SERVICE, "")
    key = store.service_keys.get(service)
    body = await request.body()
    path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    try:
        if key is None:
            raise HmacError("layanan_tidak_dikenal")
        verify(key, request.method, path, request.headers, body, store.nonces)
    except HmacError as exc:
        log.warning("token_layanan_ditolak", service=service or "-", reason=exc.reason)
        raise AstriaError("HMAC_TIDAK_VALID", "permintaan token tidak terautentikasi", 401) from exc

    try:
        req = ServiceTokenRequest.model_validate_json(body)
    except ValidationError as exc:
        raise AstriaError("VALIDASI_GAGAL", "isi permintaan token tidak valid", 400) from exc

    settings = request.app.state.settings
    if req.audience == f"svc:{service}":
        raise AstriaError("AUDIENS_DITOLAK", "token untuk diri sendiri tidak diterbitkan", 403)
    act = req.act.model_dump(exclude_none=True) if req.act else None
    if act and service not in settings.act_callers:
        raise AstriaError("ACT_DITOLAK", "layanan ini tidak boleh membawa klaim pengguna", 403)

    token, expires = issue_service_token(
        store.signing, subject=f"svc:{service}", audience=req.audience, act=act, ttl=settings.token_ttl_seconds
    )
    log.info("token_layanan_terbit", service=service, audience=req.audience, with_act=bool(act))
    payload = ServiceTokenResponse(token=token, token_type="Bearer", expires_at=expires)  # noqa: S106 - jenis token, bukan rahasia
    return JSONResponse(payload.model_dump(mode="json"), status_code=201)
