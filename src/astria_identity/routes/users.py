"""Akun, peran, dan pencabutan sesi. Aksi admin memakai klaim `act` dari api; baca satu akun cukup token layanan."""

from __future__ import annotations

from typing import Annotated

from astria_contracts.openapi.identity_internal import (
    CreateUserRequest,
    SetRolesRequest,
    UpdateUserRequest,
    User,
    UserPage,
)
from fastapi import APIRouter, Path, Query, Response

from astria_identity import events, users
from astria_identity.routes.deps import Ident, Principal

router = APIRouter(prefix="/internal/v1", tags=["users"])
UserId = Annotated[str, Path(pattern=r"^usr_[A-Za-z0-9]+$")]


@router.get("/users", response_model=UserPage)
async def list_users(
    ident: Ident,
    principal: Principal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
) -> UserPage:
    async with ident.engine.connect() as conn:
        await users.authorize_admin(ident, conn, principal, reauth=False)
        items, next_cursor = await users.list_page(conn, limit=limit, cursor=cursor)
    return UserPage.model_validate({"items": items, "next_cursor": next_cursor})


@router.post("/users", response_model=User, status_code=201)
async def create_user(body: CreateUserRequest, ident: Ident, principal: Principal) -> User:
    created = await users.create_user(
        ident,
        principal,
        username=body.username,
        display_name=body.display_name,
        password=body.password,
        role_list=[r.root for r in body.roles],
        request_id=events.new_request_id(),
    )
    return User.model_validate(created)


@router.get("/users/{user_id}", response_model=User)
async def get_user(user_id: UserId, ident: Ident, _caller: Principal) -> User:
    async with ident.engine.connect() as conn:
        return User.model_validate(await users.get(conn, user_id))


@router.patch("/users/{user_id}", response_model=User)
async def update_user(user_id: UserId, body: UpdateUserRequest, ident: Ident, principal: Principal) -> User:
    updated = await users.update_user(
        ident,
        principal,
        user_id,
        display_name=body.display_name,
        active=body.active,
        password=body.password,
    )
    return User.model_validate(updated)


@router.put("/users/{user_id}/roles", response_model=User)
async def set_roles(user_id: UserId, body: SetRolesRequest, ident: Ident, principal: Principal) -> User:
    updated = await users.set_roles(
        ident, principal, user_id, [r.root for r in body.roles], request_id=events.new_request_id()
    )
    return User.model_validate(updated)


@router.delete("/users/{user_id}/sessions", status_code=204)
async def revoke_sessions(user_id: UserId, ident: Ident, principal: Principal) -> Response:
    await users.revoke_all_sessions(ident, principal, user_id)
    return Response(status_code=204)
