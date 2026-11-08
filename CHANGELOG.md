# Changelog

## [Unreleased]

### Added

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Token layanan JWT EdDSA (`POST /internal/v1/service-tokens`, permintaan ditandatangani HMAC) dan JWKS (`GET /internal/v1/keys`); kunci tanda tangan dibuat sekali di volume.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
