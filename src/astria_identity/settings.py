"""Konfigurasi identity dari env `ASTRIA_*`."""

from pathlib import Path

from astria_common.settings import AstriaSettings


class Settings(AstriaSettings):
    service_name: str = "identity"

    signing_key_path: Path = Path("/var/lib/astria/identity/signing.pem")
    """Kunci privat Ed25519 (PEM). Dibuat saat start pertama bila belum ada; hanya identity yang membacanya."""

    service_keys_file: Path | None = None
    """JSON {"<layanan>": "<kunci hex>"}: kunci HMAC awal tiap layanan untuk meminta token."""

    act_callers: frozenset[str] = frozenset({"api"})
    """Layanan yang boleh membawa klaim `act` (pengguna pemicu) di token yang dimintanya."""

    token_ttl_seconds: int = 300

    identity_seed_file: Path | None = None
    """ASTRIA_IDENTITY_SEED_FILE: JSON {"users": [...]} pengguna dan peran dev, diterapkan idempoten saat start.
    Dilarang di `prod`; butuh ASTRIA_DATABASE_URL."""
