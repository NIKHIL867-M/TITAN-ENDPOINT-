"""Small, shared tamper-evidence layer for GEKKO persisted records.

HMAC detects accidental edits and modification by processes that cannot read
the local key. It is not claimed to resist a local Administrator who can read
both the records and key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any

INTEGRITY_FIELD = "_integrity"
ALGORITHM = "hmac-sha256"


def get_or_create_key(data_dir: Path) -> bytes:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / ".integrity.key"
    if path.exists():
        try:
            key = bytes.fromhex(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError("GEKKO integrity key is unreadable or corrupt") from exc
        if len(key) != 32:
            raise RuntimeError("GEKKO integrity key has an invalid length")
        return key

    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(key.hex())
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except OSError:
            pass
        return key
    except FileExistsError:
        # API and watcher can start together. The winner may have created the
        # directory entry but not finished flushing the key yet.
        for _ in range(20):
            try:
                key = bytes.fromhex(path.read_text(encoding="ascii").strip())
                if len(key) == 32:
                    return key
            except (OSError, ValueError):
                pass
            time.sleep(0.01)
        raise RuntimeError("GEKKO integrity key creation did not complete")


def _canonical(record: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in record.items() if key != INTEGRITY_FIELD}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sign_record(record: dict[str, Any], data_dir: Path, kind: str) -> dict[str, Any]:
    signed = dict(record)
    digest = hmac.new(get_or_create_key(data_dir), _canonical(signed), hashlib.sha256).hexdigest()
    signed[INTEGRITY_FIELD] = {
        "algorithm": ALGORITHM,
        "kind": kind,
        "digest": digest,
    }
    return signed


def verify_record(record: dict[str, Any], data_dir: Path, kind: str | None = None) -> str:
    metadata = record.get(INTEGRITY_FIELD)
    if not isinstance(metadata, dict):
        return "legacy_unsigned"
    if metadata.get("algorithm") != ALGORITHM:
        return "unsupported"
    if kind is not None and metadata.get("kind") != kind:
        return "invalid"
    supplied = str(metadata.get("digest", ""))
    expected = hmac.new(get_or_create_key(data_dir), _canonical(record), hashlib.sha256).hexdigest()
    return "verified" if hmac.compare_digest(supplied, expected) else "invalid"


def write_signed_json(path: Path, record: dict[str, Any], kind: str) -> None:
    """Atomically write a signed JSON object and flush it before replacement."""
    signed = sign_record(record, path.parent.parent if path.parent.name == "evidence" else path.parent, kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(signed, handle, indent=2, ensure_ascii=False, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
