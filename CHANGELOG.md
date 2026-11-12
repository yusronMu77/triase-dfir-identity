# Changelog

## [Unreleased]

### Added

- Subset identity#4 (issue tetap terbuka): tabel `users` dan `user_roles`, `GET /internal/v1/users/{user_id}` (token `svc:identity`, hanya `svc:api`), verifikasi token dengan kunci sendiri, seed dev `ASTRIA_IDENTITY_SEED_FILE` (idempoten, ditolak di prod).
- Dependensi `astria-common` v0.2.2 dan `astria-contracts` v0.3.0.
- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Token layanan JWT EdDSA (`POST /internal/v1/service-tokens`, permintaan ditandatangani HMAC) dan JWKS (`GET /internal/v1/keys`); kunci tanda tangan dibuat sekali di volume.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
