"""Rakit aplikasi identity Tahap 0: kunci penandatanganan, token layanan, dan JWKS.

Login, sesi, pengguna, dan pairing ditambahkan di Tahap 2 (note app-identity).
"""

from astria_common.app import create_app
from astria_common.service import standard_runtime
from fastapi import FastAPI

from astria_identity import api
from astria_identity.keys import KeyStore
from astria_identity.settings import Settings


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    runtime = standard_runtime(settings)
    runtime.add(KeyStore(settings))
    return create_app(settings, components=runtime.components, routers=[api.router])
