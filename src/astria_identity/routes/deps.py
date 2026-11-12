"""Dependensi bersama rute: konteks identity dan autentikasi pemanggil."""

from __future__ import annotations

from typing import Annotated

from astria_common.auth import ServicePrincipal, require_service
from fastapi import Depends, Request

from astria_identity.core import Identity

AUDIENCE = "svc:identity"
caller = require_service(AUDIENCE, {"svc:api"})

Principal = Annotated[ServicePrincipal, Depends(caller)]


def get_identity(request: Request) -> Identity:
    return request.app.state.identity


Ident = Annotated[Identity, Depends(get_identity)]
