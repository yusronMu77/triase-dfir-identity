"""API internal identity (kontrak token: contracts/openapi/identity-internal.yaml; pengguna: note app-identity 3.1)."""

from __future__ import annotations

from typing import Annotated

from astria_common.auth import ServicePrincipal, issue_service_token, require_service
from astria_common.errors import AstriaError
from astria_common.hmac_auth import H_SERVICE, HmacError, verify
from astria_common.log import get_logger
from astria_contracts.openapi.identity_internal import Jwks, ServiceTokenRequest, ServiceTokenResponse
from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncEngine

from astria_identity.keys import KeyStore
from astria_identity.users import USER_ID, User, get_user

log = get_logger(__name__)
router = APIRouter(prefix="/internal/v1", tags=["identity"])


def _store(request: Request) -> KeyStore:
    return request.app.state.components["keys"]


@router.get("/keys", response_model=Jwks)
async def public_keys(request: Request) -> Jwks:
    store = _store(request)
    if store.signing is None:
        raise AstriaError("KUNCI_TIDAK_TERSEDIA", "kunci penandatanganan tidak tersedia", 503)
    return Jwks.model_validate(store.jwks())


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


def _engine(request: Request) -> AsyncEngine:
    db = request.app.state.db
    if db is None or not db.is_ready:
        raise AstriaError("BASIS_DATA_TIDAK_SIAP", "direktori pengguna belum siap", 503)
    return db.engine


@router.get("/users/{user_id}", response_model=User)
async def read_user(
    request: Request,
    user_id: Annotated[str, Path(pattern=USER_ID, max_length=64)],
    _caller: Annotated[ServicePrincipal, Depends(require_service("svc:identity", {"svc:api"}))],
) -> User:
    """Pengguna dan peran saat ini untuk Command Facade api (tanpa cache di pemanggil)."""
    async with _engine(request).connect() as conn:
        user = await get_user(conn, user_id)
    if user is None:
        raise AstriaError("PENGGUNA_TIDAK_DITEMUKAN", "pengguna tidak ditemukan", 404)
    return user
