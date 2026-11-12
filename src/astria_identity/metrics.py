"""Metrik identity (note app-identity bagian 8.1). Tidak ada label yang memuat username, IP, token, atau kode."""

from prometheus_client import Counter, Gauge, Histogram

LOGIN_TOTAL = Counter("identity_login_total", "Hasil login", ["result"])
LOGIN_DURATION = Histogram(
    "identity_login_duration_seconds",
    "Waktu verifikasi kata sandi argon2 (untuk menyetel parameter)",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
SESSIONS_ACTIVE = Gauge("identity_sessions_active", "Sesi aktif (diperbarui tiap 30 detik)")
INTROSPECT_TOTAL = Counter("identity_introspect_total", "Introspeksi sesi", ["result"])
TOKEN_ISSUED = Counter("identity_token_issued_total", "Token layanan terbit", ["service"])
TOKEN_REJECTED = Counter("identity_token_rejected_total", "Permintaan token ditolak", ["reason"])
PAIRING_TOTAL = Counter("identity_pairing_total", "Kode pairing", ["result"])
KEY_DAYS = Gauge(
    "identity_key_days_to_expiry", "Hari sampai kunci perlu dirotasi (usia terhadap batas rotasi)", ["kind"]
)
