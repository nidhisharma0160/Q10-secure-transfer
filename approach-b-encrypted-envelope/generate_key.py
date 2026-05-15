"""
generate_key.py — Write 32 cryptographically random bytes to a key file.

Usage:
    python generate_key.py <key_file_path>
"""

import os
import sys
import argparse

# ── Constants ────────────────────────────────────────────────────────────────
KEY_SIZE: int = 32          # bytes — matches AES-256 and HMAC-SHA256 key length
FILE_MODE: int = 0o600      # owner read/write only


def generate_key(dest: str) -> None:
    key = os.urandom(KEY_SIZE)
    with open(dest, "wb") as fh:
        fh.write(key)
    os.chmod(dest, FILE_MODE)
    print(f"[+] {KEY_SIZE}-byte PSK written to '{dest}' (mode {oct(FILE_MODE)})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a 32-byte pre-shared key for envelope transfer."
    )
    parser.add_argument("key_file", help="Destination path for the key file")
    args = parser.parse_args()

    if os.path.exists(args.key_file):
        print(
            f"[!] '{args.key_file}' already exists. Delete it first to avoid accidents.",
            file=sys.stderr,
        )
        sys.exit(1)

    generate_key(args.key_file)


if __name__ == "__main__":
    main()
