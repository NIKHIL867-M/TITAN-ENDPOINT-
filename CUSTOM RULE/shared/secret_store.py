"""
Windows DPAPI-backed local secret storage — `shared/secret_store.py`

Plaintext API keys sitting in a .env file inside a OneDrive-synchronised
folder are one accidental share/backup/screenshot/sync-conflict away from
leaking (see FORU.TXT's constructive review, "CUSTOM RULE SECRET HANDLING").

DPAPI (CryptProtectData/CryptUnprotectData) ties the encrypted blob to this
specific Windows user account on this specific machine — it is safe for the
encrypted file to sit inside a synced folder because decrypting it requires
also being logged in as this Windows user; the ciphertext alone is useless.

This does NOT rotate a key that has already been exposed in plaintext —
only the account owner can do that (via the provider's own console). It
prevents the NEXT exposure, not retroactively undo one that's already out.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    import win32crypt
    _DPAPI_AVAILABLE = True
except ImportError:
    _DPAPI_AVAILABLE = False


def dpapi_available() -> bool:
    """False on non-Windows or when pywin32 isn't installed — callers must
    fall back to the plaintext .env path in that case, not crash."""
    return _DPAPI_AVAILABLE


def encrypt_secret(plaintext: str, description: str = "GEKKO secret") -> bytes:
    """Encrypt for the current Windows user only (no CRYPTPROTECT_LOCAL_MACHINE flag —
    that would make it readable by any user on the machine, defeating the point)."""
    if not _DPAPI_AVAILABLE:
        raise RuntimeError("pywin32's win32crypt is not available — cannot use DPAPI on this system")
    return win32crypt.CryptProtectData(plaintext.encode("utf-8"), description, None, None, None, 0)


def decrypt_secret(blob: bytes) -> str:
    if not _DPAPI_AVAILABLE:
        raise RuntimeError("pywin32's win32crypt is not available — cannot use DPAPI on this system")
    _description, plaintext = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
    return plaintext.decode("utf-8")


def save_encrypted_secret(path: Path, plaintext: str, description: str = "GEKKO secret") -> None:
    """Atomic write, same tmp+os.replace pattern used everywhere else in this project."""
    blob = encrypt_secret(plaintext, description)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, path)


def load_encrypted_secret(path: Path) -> str | None:
    """
    Returns None (never raises) if the file doesn't exist, DPAPI isn't
    available, or the blob can't be decrypted (e.g. copied to a different
    machine or user account — DPAPI keys are not portable, by design).
    """
    if not _DPAPI_AVAILABLE:
        return None
    try:
        blob = path.read_bytes()
    except OSError:
        return None
    try:
        return decrypt_secret(blob)
    except Exception:
        return None
