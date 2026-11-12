"""Token layanan (HMAC), kunci publik (JWKS), dan rotasi kunci HMAC layanan."""

from __future__ import annotations

from typing import Annotated

from astria_common.hmac_auth import H_SERVICE
from astria_contracts.openapi.identity_internal import Jwks, RotatedServiceKey, ServiceTokenResponse
from fastapi import APIRouter, Path, Request
from fastapi.responses import JSONResponse

from astria_identity import events, tokens
from astria_identity.routes.deps import Ident, Principal

router = APIRouter(prefix="/internal/v1", tags=["tokens"])


@router.get("/keys", response_model=Jwks)
async def public_keys(ident: Ident) -> Jwks:
    return Jwks.model_validate(await tokens.jwks(ident))


@router.post("/service-tokens", status_code=201, response_model=ServiceTokenResponse)
async def service_token(request: Request, ident: Ident) -> JSONResponse:
    path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    token, expires = await tokens.issue(
        ident,
        service=request.headers.get(H_SERVICE, ""),
        method=request.method,
        path=path,
        headers=request.headers,
        body=await request.body(),
    )
    payload = ServiceTokenResponse(token=token, token_type="Bearer", expires_at=expires)  # noqa: S106 - jenis token
    return JSONResponse(payload.model_dump(mode="json"), status_code=201)


@router.post("/service-keys/{service}/rotate", response_model=RotatedServiceKey, status_code=201)
async def rotate_service_key(
    service: Annotated[str, Path(pattern=r"^[a-z][a-z0-9-]*$")], ident: Ident, principal: Principal
) -> RotatedServiceKey:
    rotated = await tokens.rotate_service_key(ident, principal, service, request_id=events.new_request_id())
    return RotatedServiceKey.model_validate(rotated)
