"""
One-time migration: move GROQ_API_KEY out of the plaintext .env file into a
Windows-DPAPI-encrypted file tied to this Windows user account.

Run once:
    python scripts/migrate_secret_to_dpapi.py

After it succeeds, blank the GROQ_API_KEY line in .env (this script does
that for you, after confirming the encrypted copy round-trips correctly).
The encrypted copy takes priority automatically from then on — see
app/config.py's _maybe_load_dpapi_secrets().

This does NOT rotate the key. If it has already been exposed (e.g. via
OneDrive sync of the plaintext .env, a screenshot, a shared folder), only
rotating it at https://console.groq.com actually closes that exposure —
that step requires the account owner and cannot be done by this script.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from dotenv import dotenv_values  # noqa: E402

from shared.secret_store import (  # noqa: E402
    dpapi_available, load_encrypted_secret, save_encrypted_secret,
)


def main() -> int:
    if not dpapi_available():
        print("pywin32's win32crypt is not available — cannot migrate on this system.")
        return 1

    env_path = _ROOT / ".env"
    values = dotenv_values(env_path)
    key = (values.get("GROQ_API_KEY") or "").strip()
    if not key or key == "your_api_key_here":
        print("No real GROQ_API_KEY found in .env — nothing to migrate.")
        return 1

    secret_path = _ROOT / "data" / "secrets" / "groq_api_key.dpapi"
    save_encrypted_secret(secret_path, key, description="GEKKO GROQ_API_KEY")

    # Verify the round trip before touching the plaintext copy — never leave
    # the key unrecoverable if DPAPI encryption silently produced garbage.
    roundtrip = load_encrypted_secret(secret_path)
    if roundtrip != key:
        print("ERROR: encrypted copy did not round-trip correctly — .env left untouched.")
        return 1

    print(f"Encrypted GROQ_API_KEY saved to {secret_path}")
    print("(readable only by this Windows user account on this machine)")

    lines = env_path.read_text(encoding="utf-8").splitlines()
    rewritten = []
    blanked = False
    for line in lines:
        if line.strip().startswith("GROQ_API_KEY="):
            rewritten.append("GROQ_API_KEY=")
            blanked = True
        else:
            rewritten.append(line)
    if blanked:
        env_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        print(f"Blanked the plaintext GROQ_API_KEY line in {env_path}")

    print()
    print("Migration complete. The app will now read the key from the DPAPI file.")
    print("If this key has ever been exposed, also rotate it at https://console.groq.com.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
