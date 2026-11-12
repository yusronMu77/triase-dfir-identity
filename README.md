<!-- astria-logo -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/astria-logo-reverse.svg">
    <img src=".github/assets/astria-logo.svg" alt="Astria" width="320">
  </picture>
</p>

# Astria identity

Akun, peran, dan sesi.

> Status: versi penuh (identity#4): login, sesi, peran, pairing, token layanan, kunci. Kontrak: `contracts/openapi/identity-internal.yaml` dan `contracts/events/identity.revoked.schema.json` (contracts v0.4.0). Repo ini adalah submodule dari workspace `triase-dfir` (folder `identity/`). Rancangan: `notes/2026-11-06-triase-dfir-app-identity.md` di repo root. Lajur developer: 3.

## Tech stack

Python 3.14, FastAPI, SQLAlchemy Core async (PostgreSQL 18; SQLite untuk uji lokal), argon2id (argon2-cffi), AES-256-GCM dan Ed25519 (cryptography), uv

## Yang dilakukan

| Bagian | Perilaku |
|---|---|
| Login dan sesi | Token sesi opak 32 byte; hanya SHA-256 yang disimpan. Idle 30 menit, batas mutlak 8 jam, re-autentikasi berlaku 5 menit. Peran dibaca dari basis data pada tiap introspeksi, jadi pencabutan peran langsung berlaku. |
| Kata sandi | argon2id (m=19456 KiB, t=2, p=1). Verifikasi selalu dijalankan (hash dummy bila akun tidak ada), jadi akun yang tidak ada dan kata sandi salah tidak bisa dibedakan. Minimal 12 karakter, bukan username, bukan satu karakter berulang. |
| Throttle | Percobaan gagal dicatat di `login_attempts`: 5 per akun dan 20 per IP dalam 15 menit; klaim pairing 5 per identitas kanal dalam 10 menit. Lewat batas: 429 dengan `Retry-After`. |
| Akun dan peran | Hanya admin (klaim `act` dari api, peran dibaca dari DB, bukan dari klaim) yang membuat akun, mengganti peran, atau menonaktifkan; aksi sensitif memerlukan re-autentikasi segar. Admin aktif terakhir tidak bisa dicabut atau dinonaktifkan. |
| Pairing | Kode 8 karakter Crockford base32, berlaku 10 menit, sekali pakai; hanya hash yang disimpan; klaim atomik (`UPDATE ... WHERE used_at IS NULL`). |
| Token layanan | `POST /internal/v1/service-tokens`: HMAC dari kunci per layanan (terenkripsi di DB), matriks audiens `allowed_aud`, klaim `act` hanya dari api dan hanya untuk pengguna aktif dengan sesi aktif. JWT EdDSA, TTL 5 menit. |
| Kunci | Kunci tanda tangan Ed25519 di berkas, kunci induk AES-GCM di berkas (0600); JWKS memuat kunci aktif dan kunci overlap 24 jam. Kunci HMAC layanan dirotasi lewat API (overlap 24 jam). |
| Audit | Aksi sensitif (akun dibuat, peran berubah, kunci dirotasi) dicatat sinkron ke audit dan fail-closed: audit mati berarti aksi ditolak (503) dan tidak ada yang berubah. Login, logout, reauth, dan penolakan token dicatat lewat outbox. Event `identity.revoked` lewat outbox di transaksi yang sama dengan pencabutan. |

## Menyiapkan

1. Isi `ASTRIA_DATABASE_URL` (PostgreSQL), `ASTRIA_SIGNING_KEY_PATH` (folder yang bisa ditulis; kunci dan `master.key` dibuat saat start pertama, izin 0600) dan `ASTRIA_SERVICE_KEYS_FILE` (JSON `{"<layanan>": "<kunci 32 byte hex>"}`; disemai terenkripsi sekali, rotasi sesudahnya lewat API).
2. Admin pertama: `IDENTITY_BOOTSTRAP_PASSWORD='...' astria-identity bootstrap-admin --username <nama>` (tanpa variabel itu, kata sandi diminta tanpa gema). Menolak bila admin sudah ada, kecuali `--force`. Kata sandi tidak pernah lewat argumen.
3. Rotasi kunci tanda tangan: `astria-identity rotate-signing-key`. Kunci lama tetap sah 24 jam; layanan yang berjalan memuat berkas baru dalam sekitar 30 detik, jadi tidak perlu restart.
4. `astria-identity verify-config` memeriksa konfigurasi dan kunci tanpa menjalankan layanan.

Pengguna dev (hanya dev, `ASTRIA_ENV=prod` menolak): `ASTRIA_SEED_USERS_FILE` menunjuk JSON `[{"username","password","roles","user_id"?,"display_name"?}]`.

## Konfigurasi

Semua dengan awalan `ASTRIA_` (selain yang disebut di atas).

| Variabel | Bawaan | Arti |
|---|---|---|
| `MASTER_KEY_PATH` | `master.key` di folder kunci tanda tangan | Kunci induk AES-256-GCM (32 byte) |
| `ALLOWED_AUD` | lihat `settings.py` | JSON matriks `{"<pemanggil>": ["<audiens>", ...], "_default": [...]}`; `*` = semua audiens |
| `ACT_CALLERS` | `["api"]` | Layanan yang boleh membawa klaim `act` |
| `TOKEN_TTL_SECONDS` | 300 | 30 sampai 600 |
| `SESSION_IDLE_MINUTES`, `SESSION_MAX_HOURS`, `REAUTH_WINDOW_MINUTES` | 30, 8, 5 | Masa sesi |
| `LOGIN_FAIL_LIMIT_USER`, `LOGIN_FAIL_LIMIT_IP`, `LOGIN_FAIL_WINDOW_MINUTES` | 5, 20, 15 | Throttle login |
| `PAIRING_TTL_MINUTES`, `PAIRING_CLAIM_LIMIT`, `PAIRING_CLAIM_WINDOW_MINUTES` | 10, 5, 10 | Pairing |
| `ARGON2_MEMORY_KIB`, `ARGON2_TIME_COST`, `ARGON2_PARALLELISM` | 19456, 2, 1 | Biaya argon2id |
| `KEY_OVERLAP_HOURS`, `KEY_ROTATION_DAYS` | 24, 90 | Overlap rotasi; ambang gauge `identity_key_days_to_expiry` |

## Catatan untuk pemanggil (api, config, gateway)

- Semua endpoint `/internal/v1/*` (kecuali `service-tokens`, yang memakai HMAC, dan `keys`, yang publik) hanya menerima token `svc:api` beraudiens `svc:identity`.
- Token `act` yang di-cache oleh pemanggil bisa membawa `reauth_at` yang sudah basi. Identity memeriksa sesi di basis data pada tiap aksi admin, jadi aksi di identity aman. Layanan lain yang memakai `act.reauth_at` (mis. config) harus menerbitkan token `act` baru setelah reauth, atau menanyakan ke identity.
- `identity.revoked` (peran berubah, kata sandi diganti, akun dinonaktifkan, sesi dicabut) di-publish lewat outbox; konsumen harus menghentikan sesi dan stream WebSocket pengguna itu.

## Perintah

```text
uv sync                                   # butuh akses ke repo privat contracts dan common (tag git)
uv run ruff format --check . && uv run ruff check .
uv run pytest                              # SQLite sementara; tambahkan ASTRIA_TEST_DATABASE_URL untuk uji integrasi PostgreSQL (skema sementara, dihapus sesudahnya)
sh ../common/template/localtest.sh        # di kontainer py devenv: uji terhadap salinan kerja common dan contracts
```

Menjalankan bersama layanan lain: `pwsh ../devenv/scripts/dev.ps1 up`, lalu `dev.ps1 smoke`.

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
