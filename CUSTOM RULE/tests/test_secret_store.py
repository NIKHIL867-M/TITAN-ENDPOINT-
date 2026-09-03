"""Tests for shared/secret_store.py's DPAPI-backed local secret storage."""
import pytest

from shared.secret_store import (
    dpapi_available, encrypt_secret, decrypt_secret,
    save_encrypted_secret, load_encrypted_secret,
)

pytestmark = pytest.mark.skipif(not dpapi_available(), reason="DPAPI requires pywin32 on Windows")


def test_encrypt_decrypt_round_trip():
    blob = encrypt_secret("super-secret-value", "test")
    assert blob != b"super-secret-value"  # must actually be encrypted, not passthrough
    assert decrypt_secret(blob) == "super-secret-value"


def test_save_and_load_encrypted_secret(tmp_path):
    path = tmp_path / "secrets" / "test.dpapi"
    save_encrypted_secret(path, "another-secret", "test")
    assert path.exists()
    # Ciphertext on disk must not contain the plaintext.
    assert b"another-secret" not in path.read_bytes()
    assert load_encrypted_secret(path) == "another-secret"


def test_load_missing_file_returns_none(tmp_path):
    assert load_encrypted_secret(tmp_path / "does_not_exist.dpapi") is None


def test_load_corrupted_file_returns_none_not_raise(tmp_path):
    path = tmp_path / "corrupted.dpapi"
    path.write_bytes(b"not a real DPAPI blob")
    assert load_encrypted_secret(path) is None


def test_save_is_atomic_tmp_file_cleaned_up(tmp_path):
    path = tmp_path / "secrets" / "test.dpapi"
    save_encrypted_secret(path, "value", "test")
    leftover_tmp_files = list((tmp_path / "secrets").glob("*.tmp"))
    assert leftover_tmp_files == []
