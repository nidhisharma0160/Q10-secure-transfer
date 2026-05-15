"""
sender.py — Encrypted envelope sender over plain TCP.

Usage:
    python sender.py <file> [--key-file PATH] [--host HOST] [--port PORT]

The PSK path may also be set via the ENVELOPE_KEY_FILE environment variable.
"""

import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time
import argparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ────────────────────────────────────────────────────────────────
CHUNK_SIZE: int         = 1 * 1024 * 1024   # 1 MB plaintext per chunk
NONCE_SIZE: int         = 12                # bytes — AES-GCM standard nonce
KEY_SIZE: int           = 32                # bytes — AES-256 / HMAC-SHA256
SEQ_AAD_SIZE: int       = 8                 # bytes for sequence-number AAD
MANIFEST_VERSION: int   = 1
HMAC_DIGESTMOD: str     = "sha256"
LENGTH_FMT: str         = ">I"             # big-endian uint32 frame-length prefix
LENGTH_SIZE: int        = struct.calcsize(LENGTH_FMT)
DEFAULT_HOST: str       = "127.0.0.1"
DEFAULT_PORT: int       = 9876
ENV_KEY_VAR: str        = "ENVELOPE_KEY_FILE"


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_key(path: str) -> bytes:
    """Read and validate the 32-byte pre-shared key."""
    with open(path, "rb") as fh:
        key = fh.read()
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be exactly {KEY_SIZE} bytes; got {len(key)}")
    return key


def send_framed(sock: socket.socket, data: bytes) -> None:
    """Write a length-prefixed frame (4-byte big-endian uint32 + payload)."""
    sock.sendall(struct.pack(LENGTH_FMT, len(data)) + data)


def compute_file_sha256(filepath: str) -> str:
    """Stream-hash the file in CHUNK_SIZE blocks; return hex digest."""
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        while (block := fh.read(CHUNK_SIZE)):
            h.update(block)
    return h.hexdigest()


def seq_aad(seq: int) -> bytes:
    """Encode the sequence number as 8 big-endian bytes for AEAD AAD."""
    return seq.to_bytes(SEQ_AAD_SIZE, "big")


def encrypt_chunk(aesgcm: AESGCM, seq: int, plaintext: bytes) -> bytes:
    """
    Encrypt one chunk with AES-GCM.

    Wire layout: nonce (12 B) || ciphertext+tag (len+16 B)
    AAD: seq number (8 B big-endian) — prevents chunk reordering.
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, seq_aad(seq))
    return nonce + ciphertext


def build_manifest(filename: str, file_sha256: str,
                   total_chunks: int, timestamp: int) -> dict:
    return {
        "version":      MANIFEST_VERSION,
        "filename":     filename,
        "file_sha256":  file_sha256,
        "total_chunks": total_chunks,
        "timestamp":    timestamp,
    }


def sign_manifest(key: bytes, manifest: dict) -> str:
    """HMAC-SHA256 over canonical (sorted-key) JSON; return hex string."""
    payload = json.dumps(manifest, sort_keys=True).encode("utf-8")
    return hmac.new(key, payload, HMAC_DIGESTMOD).hexdigest()


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted envelope sender")
    parser.add_argument("file",       help="Path to the file to send")
    parser.add_argument("--key-file", default=os.environ.get(ENV_KEY_VAR),
                        help=f"PSK file (or set {ENV_KEY_VAR})")
    parser.add_argument("--host",     default=DEFAULT_HOST)
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    if not args.key_file:
        print(f"[!] Provide --key-file or set {ENV_KEY_VAR}", file=sys.stderr)
        sys.exit(1)

    key    = load_key(args.key_file)
    aesgcm = AESGCM(key)

    filepath    = args.file
    filename    = os.path.basename(filepath)
    file_size   = os.path.getsize(filepath)
    total_chunks = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE) if file_size else 0

    print(f"[*] Computing SHA-256 of '{filename}'…")
    file_sha256 = compute_file_sha256(filepath)
    print(f"[*] SHA-256 : {file_sha256}")
    print(f"[*] Size    : {file_size} bytes  |  Chunks: {total_chunks}")

    with socket.create_connection((args.host, args.port)) as sock:
        print(f"[*] Connected to {args.host}:{args.port}")

        # ── 1. Send header ────────────────────────────────────────────────
        header = json.dumps({
            "filename":     filename,
            "file_size":    file_size,
            "total_chunks": total_chunks,
        }).encode("utf-8")
        send_framed(sock, header)

        # ── 2. Send encrypted chunks ──────────────────────────────────────
        with open(filepath, "rb") as fh:
            for seq in range(total_chunks):
                plaintext = fh.read(CHUNK_SIZE)
                if not plaintext:
                    break
                frame = encrypt_chunk(aesgcm, seq, plaintext)
                send_framed(sock, frame)
                print(f"[*] Chunk {seq + 1}/{total_chunks} sent "
                      f"({len(plaintext):,} plain → {len(frame):,} wire bytes)")

        # ── 3. Send signed manifest ───────────────────────────────────────
        manifest  = build_manifest(filename, file_sha256,
                                   total_chunks, int(time.time()))
        mac_hex   = sign_manifest(key, manifest)
        envelope  = json.dumps({"manifest": manifest, "hmac": mac_hex}).encode("utf-8")
        send_framed(sock, envelope)

        print(f"[+] Manifest sent (HMAC: {mac_hex[:16]}…)")
        print("[+] Transfer complete.")


if __name__ == "__main__":
    main()
