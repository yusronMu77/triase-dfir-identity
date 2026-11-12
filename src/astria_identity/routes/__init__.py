"""Rute API internal identity (kontrak: contracts/openapi/identity-internal.yaml)."""

from fastapi import APIRouter

from astria_identity.routes import auth, pairing, tokens, users

routers: list[APIRouter] = [auth.router, users.router, pairing.router, tokens.router]
