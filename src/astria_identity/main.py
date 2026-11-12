"""Rakit aplikasi identity: kunci penandatanganan, token layanan, JWKS, dan direktori pengguna minimal.

Login, sesi, admin pengguna, dan pairing ditambahkan kemudian (note app-identity, identity#4).
"""

from astria_common.app import create_app
from astria_common.auth import JwksSource, ServiceTokenVerifier
from astria_common.envguard import EnvironmentGuardError
from astria_common.service import standard_runtime
from fastapi import FastAPI

from astria_identity import api
from astria_identity.keys import KeyStore
from astria_identity.settings import Settings
from astria_identity.users import Seeder, load_seed, metadata


def _self_verifier(keys: KeyStore) -> ServiceTokenVerifier:
    """identity adalah penerbit token: verifikasi dengan kunci publiknya sendiri, tanpa memanggil diri lewat HTTP."""

    return ServiceTokenVerifier(JwksSource("http://identity.local", fetch=keys.jwks))


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.identity_seed_file is not None and settings.env == "prod":
        raise EnvironmentGuardError(settings.env, ["berkas seed dev (ASTRIA_IDENTITY_SEED_FILE) dilarang di produksi"])
    runtime = standard_runtime(settings, metadata=[metadata])
    keys = KeyStore(settings)
    runtime.add(keys)
    if settings.identity_seed_file is not None:
        runtime.add(Seeder(runtime.require_db(), load_seed(settings.identity_seed_file)))
    app = create_app(settings, components=runtime.components, routers=[api.router], token_verifier=_self_verifier(keys))
    app.state.db = runtime.db
    return app
