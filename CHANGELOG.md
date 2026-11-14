# Changelog

## [Unreleased]

### Added

- infra#9: pagar `ASTRIA_ENV` (`astria_common.envguard`) juga dijalankan untuk `migrate`, `bootstrap-admin`, dan `rotate-signing-key` sebelum basis data atau berkas kunci disentuh; `verify-config` melaporkan pelanggarannya. Uji gagal-mulai `tests/test_startup_env.py` lewat titik masuk `astria-identity`.

- Migrasi Alembic: baseline `0001_baseline` untuk tabel identity dan outbox `astria-common`, berjalan di PostgreSQL dan SQLite. Start memakai `upgrade head`, atau `stamp head` tanpa DDL untuk DB lama yang dibuat lewat `create_all`; sebagian tabel ditolak. Komponen `migrations` di /ready.
- Perintah `astria-identity migrate` (dan `--stamp`).
- Uji migrasi `tests/test_migrations.py`: baseline dari kosong sama dengan metadata, stamp tanpa DDL, idempoten, skema sebagian ditolak, dan jalur start.
- Versi penuh (identity#4, contracts v0.4.0): login, logout, reauth, introspeksi sesi; akun, peran, pencabutan sesi; kode pairing; throttle login dan klaim; rotasi kunci HMAC layanan; matriks audiens dan klaim `act` tervalidasi di basis data; JWKS dengan kunci overlap; event `identity.revoked` dan audit lewat outbox; audit sinkron fail-closed untuk aksi sensitif.
- Perintah operator `astria-identity bootstrap-admin | rotate-signing-key | verify-config`.
- Janitor latar (muat ulang kunci, gauge sesi dan umur kunci, pembersihan data lama) dan metrik `identity_*`.
- Uji: unit, API (SQLite), keamanan (log tanpa rahasia, tanpa enumerasi akun), dan integrasi PostgreSQL (CI memakai service postgres).

### Changed

- Deskripsi peran memakai istilah yang lazim: "feedback" (bukan "umpan balik") dan "secret" (bukan "rahasia"). Hanya teks; kode peran tidak berubah.
- `astria-common` v0.2.3 (menyematkan `astria-contracts` v0.4.0). `override-dependencies` dihapus.
- Pembuatan skema saat start: `create_all` diganti migrasi. `bootstrap-admin` dan `rotate-signing-key` memigrasikan skema dulu.
- Basis data (`ASTRIA_DATABASE_URL`) kini wajib; kunci HMAC layanan disimpan terenkripsi di DB (berkas hanya menyemai).
- CI: service PostgreSQL untuk uji integrasi; smoke `/ready` memakai SQLite.

### Removed

- Router Tahap 0 (`api.py`) dan uji token Tahap 0, diganti `routes/` dan `tests/test_tokens.py`.

### Added (Tahap 0)

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Token layanan JWT EdDSA (`POST /internal/v1/service-tokens`, permintaan ditandatangani HMAC) dan JWKS (`GET /internal/v1/keys`); kunci tanda tangan dibuat sekali di volume.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
