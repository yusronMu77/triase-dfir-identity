<!-- astria-logo -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/astria-logo-reverse.svg">
    <img src=".github/assets/astria-logo.svg" alt="Astria" width="320">
  </picture>
</p>

# Astria identity

Akun, peran, dan sesi.

> Status: Tahap 0, kerangka layanan dari templat `common` v0.1.0, kini memakai `common` v0.2.2 dan `contracts` v0.3.0 (`/health`, `/ready`, `/metrics`, token layanan, Dockerfile, CI). Repo ini adalah submodule dari workspace `triase-dfir` (folder `identity/`). Rancangan: `notes/2026-11-06-triase-dfir-app-identity.md` di repo root. Lajur developer: 3.

## Direktori pengguna minimal (subset identity#4)

Hanya jalur baca untuk Command Facade `api` dan seed dev; login, sesi, kata sandi, pairing, dan endpoint admin pengguna masih milik identity#4.

| Endpoint | Pemanggil | Isi |
|---|---|---|
| `GET /internal/v1/users/{user_id}` | token layanan `svc:identity`, hanya `svc:api` | `{user_id, username, display_name, roles, active}`; 404 `PENGGUNA_TIDAK_DITEMUKAN` |

- Tabel `users` dan `user_roles` (SQLAlchemy Core, `create_all`). Peran dibatasi `analis`, `dfir`, `pimpinan`, `admin`; username unik tanpa membedakan huruf besar.
- identity memverifikasi token layanan dengan kunci publiknya sendiri (tanpa memanggil `/internal/v1/keys` lewat HTTP).
- Seed dev: `ASTRIA_IDENTITY_SEED_FILE` berisi `{"users": [{"user_id", "username", "display_name", "roles", "active"}]}`. Divalidasi saat start, diterapkan idempoten setelah basis data siap (peran pengguna seed diganti persis), `/ready` menunggu seed. Ditolak di `ASTRIA_ENV=prod` dan tanpa `ASTRIA_DATABASE_URL`. Contoh: `devenv/identity/seed.json`.

## Tech stack

Python 3.14, FastAPI, PostgreSQL 18, uv

## Perintah

```text
uv sync                                   # butuh akses ke repo privat contracts dan common (tag git)
uv run ruff format --check . && uv run ruff check .
uv run pytest
sh ../common/template/localtest.sh        # di kontainer py devenv: uji terhadap salinan kerja common dan contracts
```

Menjalankan bersama layanan lain: `pwsh ../devenv/scripts/dev.ps1 up`, lalu `dev.ps1 smoke`.

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
