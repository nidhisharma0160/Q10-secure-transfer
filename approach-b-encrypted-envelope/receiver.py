"""
receiver.py — Encrypted envelope receiver over plain TCP.

Usage:
    python receiver.py [--key-file PATH] [--host HOST] [--port PORT]
                       [--output-dir DIR]

The PSK path may also be set via the ENVELOPE_KEY_FILE environment variable.

Security invariants enforced:
  • AES-GCM tag checked per chunk (InvalidTag → immediate abort + cleanup).
  • Chunk sequence number in AAD prevents reordering / splicing.
  • Manifest HMAC verified before touching the filesystem rename.
  • File SHA-256 checked against manifest after all chunks are written.
  • All data written to <filename>.tmp; atomic rename only after full verification.
  • On any failure the .tmp file is deleted and the process exits non-zero.
"""

import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import argparse
from time import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ────────────────────────────────────────────────────────────────
CHUNK_SIZE: int         = 1 * 1024 * 1024   # must match sender
NONCE_SIZE: int         = 12
KEY_SIZE: int           = 32
SEQ_AAD_SIZE: int       = 8
MANIFEST_VERSION: int   = 1
HMAC_DIGESTMOD: str     = "sha256"
LENGTH_FMT: str         = ">I"
LENGTH_SIZE: int        = struct.calcsize(LENGTH_FMT)
DEFAULT_HOST: str       = "0.0.0.0"
DEFAULT_PORT: int       = 9876
ENV_KEY_VAR: str        = "ENVELOPE_KEY_FILE"
TMP_SUFFIX: str         = ".tmp"
MAX_FILENAME_LEN: int   = 255               # POSIX limit


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_key(path: str) -> bytes:
    with open(path, "rb") as fh:
        key = fh.read()
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be exactly {KEY_SIZE} bytes; got {len(key)}")
    return key


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Block until exactly n bytes have been received."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before all bytes arrived")
        buf.extend(chunk)
    return bytes(buf)


def recv_framed(sock: socket.socket) -> bytes:
    """Read a length-prefixed frame; return its payload."""
    raw_len = recv_exact(sock, LENGTH_SIZE)
    payload_len = struct.unpack(LENGTH_FMT, raw_len)[0]
    return recv_exact(sock, payload_len)


def seq_aad(seq: int) -> bytes:
    return seq.to_bytes(SEQ_AAD_SIZE, "big")


def decrypt_chunk(aesgcm: AESGCM, seq: int, frame: bytes) -> bytes:
    """
    Decrypt one frame.  Raises cryptography.exceptions.InvalidTag on
    authentication failure (tampered ciphertext, wrong key, or wrong seq).
    """
    if len(frame) < NONCE_SIZE:
        raise ValueError(f"Frame too short to contain nonce: {len(frame)} bytes")
    nonce      = frame[:NONCE_SIZE]
    ciphertext = frame[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ciphertext, seq_aad(seq))


def verify_manifest_hmac(key: bytes, manifest: dict, mac_hex: str) -> bool:
    payload  = json.dumps(manifest, sort_keys=True).encode("utf-8")
    expected = hmac.new(key, payload, HMAC_DIGESTMOD).digest()
    try:
        received = bytes.fromhex(mac_hex)
    except ValueError:
        return False
    return hmac.compare_digest(expected, received)


def sanitize_filename(raw: str) -> str:
    """Strip directory components and reject obviously dangerous names."""
    name = os.path.basename(raw)
    if not name or name in (".", "..") or len(name) > MAX_FILENAME_LEN:
        raise ValueError(f"Rejected filename: {raw!r}")
    return name


def cleanup_and_fail(tmp_path: str | None, reason: str, code: int = 1) -> None:
    """Delete temp file (if it exists), print error, and exit non-zero."""
    print(f"\n[!] VERIFICATION FAILED — {reason}", file=sys.stderr)
    if tmp_path and os.path.exists(tmp_path):
        try:
            os.remove(tmp_path)
            print(f"[*] Deleted temp file: {tmp_path}", file=sys.stderr)
        except OSError as exc:
            print(f"[!] Could not delete temp file: {exc}", file=sys.stderr)
    sys.exit(code)


# ── Transfer handler ─────────────────────────────────────────────────────────

def handle_transfer(conn: socket.socket, key: bytes, output_dir: str) -> None:
    aesgcm   = AESGCM(key)
    tmp_path = None

    try:
        # ── 1. Receive and parse header ───────────────────────────────────
        header       = json.loads(recv_framed(conn).decode("utf-8"))
        filename     = sanitize_filename(header["filename"])
        total_chunks = int(header["total_chunks"])
        file_size    = int(header["file_size"])

        print(f"[*] Incoming : '{filename}'  ({file_size:,} bytes, {total_chunks} chunks)")

        final_path = os.path.join(output_dir, filename)
        tmp_path   = final_path + TMP_SUFFIX

        hasher = hashlib.sha256()

        # ── 2. Receive, decrypt, and stream chunks to .tmp ────────────────
        with open(tmp_path, "wb") as fh:
            for seq in range(total_chunks):
                frame = recv_framed(conn)
                try:
                    plaintext = decrypt_chunk(aesgcm, seq, frame)
                except InvalidTag:
                    cleanup_and_fail(
                        tmp_path,
                        f"AES-GCM authentication tag invalid on chunk {seq} "
                        "(tampered data, wrong key, or reordering attack)"
                    )
                hasher.update(plaintext)
                fh.write(plaintext)
                print(f"[*] Chunk {seq + 1}/{total_chunks} decrypted "
                      f"({len(plaintext):,} bytes)")

        # ── 3. Receive manifest envelope ──────────────────────────────────
        envelope = json.loads(recv_framed(conn).decode("utf-8"))
        manifest = envelope["manifest"]
        mac_hex  = envelope["hmac"]

        # ── 4. Verify manifest HMAC ───────────────────────────────────────
        if not verify_manifest_hmac(key, manifest, mac_hex):
            cleanup_and_fail(tmp_path, "Manifest HMAC mismatch — possible tampering")

        # ── 4b. Verify manifest timestamp freshness (replay protection) ──
        MAX_REPLAY_WINDOW = 300  # seconds — reject manifests older than 5 minutes
        if abs(time.time() - manifest["timestamp"]) > MAX_REPLAY_WINDOW:
            cleanup_and_fail(
                tmp_path,
                f"Manifest timestamp is stale (age={int(time.time() - manifest['timestamp'])}s) "
                "— possible replay attack"
            )

        
        # ── 5. Verify manifest version ────────────────────────────────────
        if manifest.get("version") != MANIFEST_VERSION:
            cleanup_and_fail(
                tmp_path,
                f"Unsupported manifest version: {manifest.get('version')!r}"
            )

        # ── 6. Verify chunk count consistency ─────────────────────────────
        if manifest["total_chunks"] != total_chunks:
            cleanup_and_fail(
                tmp_path,
                f"Chunk-count mismatch: header said {total_chunks}, "
                f"manifest says {manifest['total_chunks']}"
            )

        # ── 7. Verify file SHA-256 ────────────────────────────────────────
        actual_sha256   = hasher.hexdigest()
        expected_sha256 = manifest["file_sha256"]

        if not hmac.compare_digest(actual_sha256, expected_sha256):
            cleanup_and_fail(
                tmp_path,
                f"File SHA-256 mismatch\n"
                f"    expected : {expected_sha256}\n"
                f"    actual   : {actual_sha256}"
            )

        # ── 8. Atomic rename — only now is the final file written ─────────
        os.rename(tmp_path, final_path)

        print(f"\n[+] All checks passed.")
        print(f"[+] SHA-256   : {actual_sha256}")
        print(f"[+] Saved to  : {final_path}")

    except (KeyError, json.JSONDecodeError, ValueError, ConnectionError) as exc:
        cleanup_and_fail(tmp_path, f"Protocol error: {exc}")
    except Exception:
        # Unexpected exception: still clean up before re-raising.
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted envelope receiver")
    parser.add_argument("--key-file",   default=os.environ.get(ENV_KEY_VAR),
                        help=f"PSK file (or set {ENV_KEY_VAR})")
    parser.add_argument("--host",       default=DEFAULT_HOST)
    parser.add_argument("--port",       type=int, default=DEFAULT_PORT)
    parser.add_argument("--output-dir", default=".",
                        help="Directory to write received files into")
    args = parser.parse_args()

    if not args.key_file:
        print(f"[!] Provide --key-file or set {ENV_KEY_VAR}", file=sys.stderr)
        sys.exit(1)

    key = load_key(args.key_file)
    os.makedirs(args.output_dir, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"[*] Listening on {args.host}:{args.port}  (output → '{args.output_dir}')")

        conn, addr = srv.accept()
        print(f"[*] Connection from {addr[0]}:{addr[1]}")
        with conn:
            handle_transfer(conn, key, args.output_dir)


if __name__ == "__main__":
    main()
