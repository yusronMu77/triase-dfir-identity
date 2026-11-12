"""Konfigurasi identity dari env `ASTRIA_*` (note app-identity bagian 5.5).

Pengaturan keamanan identity hanya dari env dan berkas rahasia; tidak ada lapisan database yang bisa diubah dari dasbor.
"""

from pathlib import Path

from astria_common.settings import AstriaSettings
from pydantic import Field, field_validator

# Matriks audiens token: layanan pemohon -> audiens yang boleh diminta. Kunci `*` pada nilai berarti semua audiens;
# kunci `_default` dipakai layanan yang tidak tercantum. Diturunkan dari pemakaian nyata di repo layanan per 2026-11-12
# (dfir, triage, verifier -> ingest; scheduler -> ticket; semua -> audit) ditambah alur rancangan
# (narrative -> config untuk model.api_key; ticket dan config -> notifier). Token untuk diri sendiri selalu ditolak.
DEFAULT_ALLOWED_AUD: dict[str, list[str]] = {
    "api": ["*"],
    "dfir": ["ingest", "audit"],
    "triage": ["ingest", "audit"],
    "verifier": ["ingest", "audit"],
    "narrative": ["config", "ingest", "audit"],
    "scheduler": ["ticket", "audit"],
    "ticket": ["audit", "notifier", "config"],
    "config": ["audit", "notifier"],
    "notifier": ["audit", "config"],
    "ingest": ["audit"],
    "seed": ["ingest", "audit"],
    "devtools": ["audit", "ingest", "config", "ticket"],
    "_default": ["audit"],
}


class Settings(AstriaSettings):
    service_name: str = "identity"

    signing_key_path: Path = Path("/var/lib/astria/identity/signing.pem")
    """Kunci privat Ed25519 (PEM). Dibuat saat start pertama bila belum ada; hanya identity yang membacanya."""

    master_key_path: Path | None = None
    """Kunci induk AES-256-GCM (32 byte mentah) untuk `service_keys.secret_enc`. Kosong = `master.key` di folder
    kunci penandatangan. Dibuat saat start pertama bila belum ada (izin 0600); simpan salinannya di luar basis data."""

    service_keys_file: Path | None = None
    """JSON {"<layanan>": "<kunci hex>"}: kunci HMAC awal tiap layanan. Disemai ke `service_keys` (terenkripsi)
    saat start; rotasi sesudahnya lewat API."""

    seed_users_file: Path | None = None
    """JSON daftar {user_id?, username, display_name, password, roles}; hanya dibaca di env selain prod. Idempoten."""

    act_callers: frozenset[str] = frozenset({"api"})
    """Layanan yang boleh membawa klaim `act` (pengguna pemicu) di token yang dimintanya."""

    allowed_aud: dict[str, list[str]] = Field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_ALLOWED_AUD.items()}
    )
    """Matriks audiens token (lihat DEFAULT_ALLOWED_AUD); dapat ditimpa penuh lewat JSON di env."""

    token_ttl_seconds: int = Field(default=300, ge=30, le=600)

    session_idle_minutes: int = Field(default=30, ge=1)
    session_max_hours: int = Field(default=8, ge=1)
    reauth_window_minutes: int = Field(default=5, ge=1)

    login_fail_limit_user: int = Field(default=5, ge=1)
    login_fail_limit_ip: int = Field(default=20, ge=1)
    login_fail_window_minutes: int = Field(default=15, ge=1)

    pairing_ttl_minutes: int = Field(default=10, ge=1)
    pairing_claim_limit: int = Field(default=5, ge=1)
    pairing_claim_window_minutes: int = Field(default=10, ge=1)

    argon2_memory_kib: int = Field(default=19456, ge=8)
    argon2_time_cost: int = Field(default=2, ge=1)
    argon2_parallelism: int = Field(default=1, ge=1)

    key_overlap_hours: int = Field(default=24, ge=1)
    key_rotation_days: int = Field(default=90, ge=1)
    """Umur kunci yang dianggap perlu dirotasi; hanya dipakai gauge `identity_key_days_to_expiry`."""

    @field_validator("allowed_aud")
    @classmethod
    def _aud_has_default(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if "_default" not in value:
            raise ValueError("allowed_aud wajib memuat kunci _default")
        return value

    @property
    def master_key_file(self) -> Path:
        return self.master_key_path or self.signing_key_path.with_name("master.key")
