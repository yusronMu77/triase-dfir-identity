"""Kunci identity: kunci penandatanganan Ed25519 dan kunci HMAC awal tiap layanan."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from astria_common.auth import SigningKey, load_or_create_signing_key
from astria_common.component import Check
from astria_common.hmac_auth import NonceCache
from astria_common.log import get_logger

from astria_identity.settings import Settings

log = get_logger(__name__)
_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


def load_service_keys(path: Path | None) -> dict[str, bytes]:
    if path is None or not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    keys: dict[str, bytes] = {}
    for name, value in raw.items():
        if not _NAME.match(name):
            raise ValueError(f"nama layanan tidak valid di berkas kunci: {name!r}")
        key = bytes.fromhex(value)
        if len(key) < 32:
            raise ValueError(f"kunci layanan {name} kurang dari 32 byte")
        keys[name] = key
    return keys


@dataclass
class KeyStore:
    """Komponen: memuat kunci saat start. /ready `down` bila kunci penandatanganan tidak tersedia."""

    settings: Settings
    name: str = "keys"
    required: bool = True
    signing: SigningKey | None = None
    service_keys: dict[str, bytes] = field(default_factory=dict)
    nonces: NonceCache = field(default_factory=NonceCache)
    error: str | None = None

    async def start(self) -> None:
        try:
            self.signing = load_or_create_signing_key(self.settings.signing_key_path)
            self.service_keys = load_service_keys(self.settings.service_keys_file)
            log.info("kunci_dimuat", kid=self.signing.kid, services=sorted(self.service_keys))
        except (OSError, ValueError) as exc:
            self.error = type(exc).__name__
            log.error("kunci_gagal_dimuat", error=self.error)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Kunci publik yang diterbitkan di `GET /internal/v1/keys`; identity juga memverifikasi tokennya dengan ini."""
        return {"keys": [self.signing.public_jwk()] if self.signing else []}

    async def stop(self) -> None:
        return None

    async def check(self) -> Check:
        if self.signing is None:
            return Check("down", f"kunci penandatanganan tidak tersedia ({self.error})")
        if not self.service_keys:
            return Check("degraded", "tidak ada kunci layanan; penerbitan token mati")
        return Check("ok", f"kid={self.signing.kid} services={len(self.service_keys)}")
