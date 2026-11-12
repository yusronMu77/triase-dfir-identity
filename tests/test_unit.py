"""Uji unit tanpa basis data: kebijakan kata sandi, argon2, kode pairing, enkripsi kunci."""

import pytest
from astria_common.errors import AstriaError

from astria_identity import keys, pairing
from astria_identity.passwords import Passwords, check_policy


def test_policy_rejects_short_same_as_username_and_repeated() -> None:
    for password, username in [("pendek", "budi"), ("Budi.Analis.1", "budi.analis.1"), ("aaaaaaaaaaaaaaaa", "budi")]:
        with pytest.raises(AstriaError) as exc:
            check_policy(password, username)
        assert exc.value.code == "KEBIJAKAN_KATA_SANDI"
        assert exc.value.status == 422
    check_policy("kata-sandi-panjang-9", "budi")


@pytest.mark.anyio
async def test_password_hash_verify_and_dummy() -> None:
    pw = Passwords(memory_kib=64, time_cost=1, parallelism=1)
    stored = await pw.hash("kata-sandi-panjang-9")
    assert stored.startswith("$argon2id$")
    assert await pw.verify(stored, "kata-sandi-panjang-9") is True
    assert await pw.verify(stored, "salah-salah-salah") is False
    # Akun tidak ada: verifikasi tetap jalan terhadap hash dummy dan tidak pernah lolos.
    assert await pw.verify(None, "kata-sandi-panjang-9") is False


def test_pairing_code_format_and_normalisation() -> None:
    for _ in range(50):
        code = pairing.generate_code()
        assert len(code) == 8
        assert set(code) <= set(pairing.ALPHABET)
    assert pairing.normalize("ab-cd 1l0o") == "ABCD1100"
    assert pairing.hash_code("abcd-1234") == pairing.hash_code("ABCD1234")


def test_master_key_encryption_binds_aad() -> None:
    master = bytes(range(32))
    blob = keys.encrypt(master, b"rahasia", aad=b"api:svk_1")
    assert keys.decrypt(master, blob, aad=b"api:svk_1") == b"rahasia"
    with pytest.raises(Exception):  # noqa: B017, PT011 - InvalidTag dari cryptography
        keys.decrypt(master, blob, aad=b"ingest:svk_1")
    assert b"rahasia" not in blob
