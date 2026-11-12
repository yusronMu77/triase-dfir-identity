"""Kata sandi: argon2id dan kebijakan. Verifikasi selalu jalan (hash dummy bila akun tidak ada): waktu respons sama."""

from __future__ import annotations

import asyncio
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from astria_common.errors import AstriaError

MIN_LENGTH = 12


def check_policy(password: str, username: str) -> None:
    """Kebijakan: minimal 12 karakter, bukan username, bukan satu karakter berulang."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"minimal {MIN_LENGTH} karakter")
    if password.casefold() == username.casefold():
        problems.append("tidak boleh sama dengan username")
    if len(set(password)) <= 1:
        problems.append("tidak boleh satu karakter berulang")
    if problems:
        raise AstriaError("KEBIJAKAN_KATA_SANDI", "kata sandi tidak memenuhi kebijakan: " + ", ".join(problems), 422)


class Passwords:
    def __init__(self, *, memory_kib: int, time_cost: int, parallelism: int) -> None:
        self._hasher = PasswordHasher(memory_cost=memory_kib, time_cost=time_cost, parallelism=parallelism)
        # Hash dummy dari kata sandi acak: tidak pernah cocok dengan masukan nyata.
        self._dummy = self._hasher.hash(secrets.token_urlsafe(24))

    def hash_sync(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify_sync(self, stored: str | None, password: str) -> bool:
        """Selalu memverifikasi: terhadap `stored`, atau hash dummy bila None. Mengembalikan True hanya bila cocok."""
        target = stored if stored is not None else self._dummy
        try:
            ok = self._hasher.verify(target, password)
        except VerifyMismatchError, VerificationError, InvalidHashError:
            return False
        return ok and stored is not None

    def needs_rehash(self, stored: str) -> bool:
        return self._hasher.check_needs_rehash(stored)

    # Argon2 memblokir CPU; jalankan di thread agar loop event tetap responsif.
    async def hash(self, password: str) -> str:
        return await asyncio.to_thread(self.hash_sync, password)

    async def verify(self, stored: str | None, password: str) -> bool:
        return await asyncio.to_thread(self.verify_sync, stored, password)
