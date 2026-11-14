"""Perintah operator: `serve` (bawaan), `migrate`, `bootstrap-admin`, `rotate-signing-key`, `verify-config`.

Kata sandi admin pertama dibaca dari `IDENTITY_BOOTSTRAP_PASSWORD` atau diminta tanpa gema; tidak dari argumen.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from collections.abc import Sequence
from datetime import timedelta

from astria_common import envguard
from astria_common.app import run
from astria_common.auth import load_or_create_signing_key
from astria_common.db import Database
from astria_common.errors import AstriaError

from astria_identity import events, passwords, users
from astria_identity.bootstrap import seed_roles
from astria_identity.clock import Clock
from astria_identity.core import Identity
from astria_identity.keys import KeyStore, load_or_create_master_key, register_signing_key, write_new_signing_key
from astria_identity.main import build_app
from astria_identity.migrate import MigrateAction, MigrationError, migrate_database
from astria_identity.passwords import Passwords
from astria_identity.settings import Settings


class _NoAudit:
    """CLI mencatat audit lewat outbox, bukan HTTP."""

    async def record(self, record: object) -> None:  # pragma: no cover - tidak dipakai CLI
        raise RuntimeError("CLI tidak memakai jalur audit sinkron")


def _open(settings: Settings) -> Database:
    if settings.database_url is None:
        raise SystemExit("ASTRIA_DATABASE_URL wajib diisi")
    return Database(settings.database_url, schema=settings.db_schema)


async def migrate(settings: Settings, *, stamp_only: bool = False) -> MigrateAction:
    """Upgrade ke head, atau stamp bila skema sudah lengkap tanpa riwayat (lihat `astria_identity.migrate`)."""
    db = _open(settings)
    await db.start()
    try:
        await db.wait_ready(timeout=30)
        return await migrate_database(db, settings, stamp_only=stamp_only)
    finally:
        await db.stop()


_MIGRATE_MESSAGES: dict[str, str] = {
    "create": "skema baru dibuat dari baseline",
    "upgrade": "migrasi dijalankan sampai head",
    "stamp": "skema lengkap tanpa riwayat ditandai head (tanpa perubahan data)",
}


async def bootstrap_admin(settings: Settings, username: str, display_name: str | None, *, force: bool) -> str:
    password = os.environ.get("IDENTITY_BOOTSTRAP_PASSWORD") or getpass.getpass("Kata sandi admin: ")
    passwords.check_policy(password, username)
    db = _open(settings)
    await db.start()
    try:
        await db.wait_ready(timeout=30)
        await migrate_database(db, settings)
        keys = KeyStore(settings)
        ident = Identity(
            settings=settings,
            db=db,
            keys=keys,
            passwords=Passwords(
                memory_kib=settings.argon2_memory_kib,
                time_cost=settings.argon2_time_cost,
                parallelism=settings.argon2_parallelism,
            ),
            audit=_NoAudit(),  # type: ignore[arg-type]
            clock=Clock(),
        )
        password_hash = await ident.passwords.hash(password)
        async with db.engine.begin() as conn:
            await seed_roles(conn)
            if not force and await users.count_admins(conn) > 0:
                raise AstriaError("ADMIN_SUDAH_ADA", "sudah ada admin; pakai --force untuk menambah", 409)
            user = await users.create(
                ident,
                conn,
                username=username,
                display_name=display_name or username,
                password_hash=password_hash,
                role_list=["admin"],
                granted_by="cli",
            )
            now = ident.clock.now()
            await events.enqueue_audit(
                conn,
                events.audit_record(
                    action="identity.user.created",
                    key=f"identity-user-created-cli-{user['user_id']}",
                    actor=events.SERVICE_ACTOR,
                    target_type="user",
                    target_id=user["user_id"],
                    payload={
                        "user_id": user["user_id"],
                        "username": username,
                        "roles": ["admin"],
                        "created_by": "cli",
                    },
                    occurred_at=now,
                    via="cli",
                ),
            )
        return user["user_id"]
    finally:
        await db.stop()


async def rotate_signing_key(settings: Settings) -> tuple[str, str]:
    """Kunci lama jadi overlap (24 jam), kunci baru aktif. Layanan yang berjalan memuat ulang berkas dalam ±30 detik."""
    db = _open(settings)
    await db.start()
    try:
        await db.wait_ready(timeout=30)
        await migrate_database(db, settings)
        old = load_or_create_signing_key(settings.signing_key_path)
        overlap = Clock().now()
        async with db.engine.begin() as conn:
            await register_signing_key(conn, old, overlap, timedelta(hours=settings.key_overlap_hours))
        new = write_new_signing_key(settings.signing_key_path)
        async with db.engine.begin() as conn:
            await register_signing_key(conn, new, Clock().now(), timedelta(hours=settings.key_overlap_hours))
        return old.kid, new.kid
    finally:
        await db.stop()


def verify_config(settings: Settings) -> list[str]:
    problems: list[str] = [f"ASTRIA_ENV={settings.env}: {p}" for p in envguard.violations(settings)]
    if settings.database_url is None:
        problems.append("ASTRIA_DATABASE_URL belum diisi")
    if settings.env == "prod" and settings.seed_users_file is not None:
        problems.append("ASTRIA_SEED_USERS_FILE tidak boleh diisi di produksi")
    try:
        load_or_create_master_key(settings.master_key_file)
        load_or_create_signing_key(settings.signing_key_path)
    except (OSError, ValueError) as exc:
        problems.append(f"kunci tidak dapat dimuat ({type(exc).__name__})")
    if "_default" not in settings.allowed_aud:
        problems.append("ALLOWED_AUD wajib punya entri _default")
    return problems


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="astria-identity")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="jalankan layanan (bawaan)")
    boot = sub.add_parser("bootstrap-admin", help="buat admin pertama")
    boot.add_argument("--username", required=True)
    boot.add_argument("--display-name")
    boot.add_argument("--force", action="store_true", help="tambah admin walau sudah ada")
    mig = sub.add_parser("migrate", help="migrasi skema ke head (membuat baseline, atau stamp skema lama)")
    mig.add_argument("--stamp", action="store_true", help="hanya tandai head; tolak skema kosong")
    sub.add_parser("rotate-signing-key", help="rotasi kunci penandatangan JWT (overlap 24 jam)")
    sub.add_parser("verify-config", help="periksa konfigurasi dan kunci tanpa menjalankan layanan")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings()
    command = args.command or "serve"
    if command != "verify-config":
        # Pagar ASTRIA_ENV sebelum basis data atau berkas kunci disentuh (serve juga diperiksa lagi di create_app).
        envguard.enforce(settings)
    if command == "serve":
        run(build_app(settings), settings)
        return 0
    if command == "verify-config":
        problems = verify_config(settings)
        for problem in problems:
            print(f"GAGAL: {problem}", file=sys.stderr)
        print("konfigurasi valid" if not problems else "konfigurasi bermasalah")
        return 1 if problems else 0
    try:
        if command == "migrate":
            action = asyncio.run(migrate(settings, stamp_only=args.stamp))
            print(f"migrasi: {_MIGRATE_MESSAGES[action]}")
        elif command == "bootstrap-admin":
            user_id = asyncio.run(bootstrap_admin(settings, args.username, args.display_name, force=args.force))
            print(f"admin dibuat: {user_id}")
        elif command == "rotate-signing-key":
            old, new = asyncio.run(rotate_signing_key(settings))
            print(f"kunci diputar: {old} -> {new} (kunci lama tetap sah selama {settings.key_overlap_hours} jam)")
    except AstriaError as exc:
        print(f"GAGAL [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    except MigrationError as exc:
        print(f"GAGAL [MIGRASI]: {exc}", file=sys.stderr)
        return 1
    return 0
