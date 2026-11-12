"""Login, logout, re-autentikasi, dan introspeksi sesi."""

from __future__ import annotations

from astria_contracts.openapi.identity_internal import (
    Introspection,
    LoginRequest,
    LoginResponse,
    ReauthRequest,
    ReauthResponse,
    TokenRequest,
)
from fastapi import APIRouter, Response

from astria_identity import sessions
from astria_identity.routes.deps import Ident, Principal

router = APIRouter(prefix="/internal/v1", tags=["auth"])


@router.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, ident: Ident, _caller: Principal) -> LoginResponse:
    client = body.client
    result = await sessions.login(
        ident,
        username=body.username,
        password=body.password,
        ip_hash=client.ip_hash if client else None,
        ua_hash=client.user_agent_hash if client else None,
    )
    return LoginResponse.model_validate(result)


@router.post("/auth/logout", status_code=204)
async def logout(body: TokenRequest, ident: Ident, _caller: Principal) -> Response:
    await sessions.logout(ident, body.token)
    return Response(status_code=204)


@router.post("/auth/reauth", response_model=ReauthResponse)
async def reauth(body: ReauthRequest, ident: Ident, _caller: Principal) -> ReauthResponse:
    return ReauthResponse.model_validate(await sessions.reauth(ident, body.token, body.password))


@router.post("/sessions/introspect", response_model=Introspection, response_model_exclude_none=True)
async def introspect(body: TokenRequest, ident: Ident, _caller: Principal) -> Introspection:
    return Introspection.model_validate(await sessions.introspect(ident, body.token))
