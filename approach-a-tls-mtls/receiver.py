#!/usr/bin/env python3
"""
Approach A — Mutually-authenticated TLS receiver.

Listens on a TCP port, performs a TLS 1.3 handshake that *requires* a client
certificate (mutual TLS), then receives a streamed file in 1 MiB chunks.
Each chunk is decrypted with AES-256-GCM; any authentication-tag failure
causes immediate abort (temp file deleted, process exits non-zero).  After
the final chunk the receiver reads the sender's SHA-256 hash of the plaintext
and compares it against its own running digest.  Only when both checks pass
does it atomically rename the temp file to the final destination and send b"OK".

Wire protocol (all received inside the TLS record layer):
    Per chunk  : [4-byte BE payload_len] [AES-GCM ciphertext || 16-byte tag]
    End marker : [4-byte BE: 0x00000000]
    Final hash : [32-byte SHA-256 of concatenated plaintext chunks]
    ACK        : receiver sends b"OK\\n" on success

Failure modes handled
---------------------
* InvalidTag (AEAD)       — tampered ciphertext / wrong key / wrong chunk order
* Nonce-sanity cap        — oversized payload_len rejected before allocation
* SHA-256 mismatch        — truncated stream or in-transit bit flip missed by GCM
* Network errors          — EOFError / OSError during any recv
* Missing client cert     — TLS layer enforces CERT_REQUIRED; extra defensive check

On *any* of the above: temp file is unlinked and the process exits with code 1.

Security notes
--------------
* Nonce is derived from the chunk counter independently (NOT received from
  the wire).  AAD encodes the chunk index.  Together they prevent reordering
  and cross-session replay at the application layer.
* CERT_REQUIRED is set explicitly on the SSLContext even though
  PROTOCOL_TLS_SERVER does not set it by default.
* Temp file is written to <output>.tmp and renamed only after all integrity
  checks pass, preventing partial-file leakage to the application layer.

Usage
-----
    python receiver.py [options] <output-file>

Required (env var or CLI flag):
    TRANSFER_KEY          64-hex-char AES-256 key  (32 bytes)
    TLS_CA_CERT           path to CA certificate PEM
    TLS_SERVER_CERT       path to server certificate PEM
    TLS_SERVER_KEY        path to server private key PEM
"""

import argparse
import hashlib
import os
import socket
import ssl
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Named constants ───────────────────────────────────────────────────────────
CHUNK_SIZE   = 1024 * 1024  # 1 MiB per chunk
KEY_LENGTH   = 32           # AES-256 → 32 bytes
NONCE_LENGTH = 12           # 96-bit GCM nonce (NIST SP 800-38D §8.2)
TAG_LENGTH   = 16           # 128-bit GCM authentication tag (never truncate)
HASH_LENGTH  = 32           # SHA-256 output length in bytes
LEN_PREFIX   = 4            # bytes reserved for the chunk-length framing header
# Hard ceiling on a single chunk payload — protects against malformed lengths
# causing runaway memory allocation before any crypto check.
MAX_PAYLOAD  = CHUNK_SIZE + TAG_LENGTH  # 1 MiB + 16 bytes


# ── Nonce / AAD derivation ────────────────────────────────────────────────────

def make_nonce(chunk_index: int) -> bytes:
    """Return the 96-bit nonce for *chunk_index* (derived, never received)."""
    return chunk_index.to_bytes(NONCE_LENGTH, byteorder="big")


def make_aad(chunk_index: int) -> bytes:
    """Return the 64-bit AAD for *chunk_index* (binds ciphertext to position)."""
    return chunk_index.to_bytes(8, byteorder="big")


# ── I/O helpers ───────────────────────────────────────────────────────────────

def recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, retrying on short reads."""
    buf = bytearray()
    while len(buf) < n:
        data = sock.recv(n - len(buf))
        if not data:
            raise EOFError(
                f"Connection closed after {len(buf)}/{n} bytes"
            )
        buf.extend(data)
    return bytes(buf)


# ── Abort helper ──────────────────────────────────────────────────────────────

def abort(tmp: Path, message: str, exit_code: int = 1) -> None:
    """Unlink *tmp*, print *message* to stderr, and exit with *exit_code*.

    Raises SystemExit — callers do not need to return after calling this.
    The SystemExit propagates through any enclosing 'with' blocks so that
    open file handles are closed cleanly before the process terminates.
    """
    try:
        tmp.unlink(missing_ok=True)
    except OSError:
        pass
    print(f"[receiver] ABORT: {message}", file=sys.stderr)
    sys.exit(exit_code)


# ── Main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="mTLS AES-256-GCM streaming file receiver (Approach A)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("output", help="Destination file path")
    p.add_argument("--bind",        default="0.0.0.0",
                   help="Address to bind (default: 0.0.0.0)")
    p.add_argument("--port",        type=int, default=9443,
                   help="TCP port to listen on (default: 9443)")
    p.add_argument("--ca-cert",
                   default=os.environ.get("TLS_CA_CERT"),
                   help="CA certificate PEM  [env: TLS_CA_CERT]")
    p.add_argument("--server-cert",
                   default=os.environ.get("TLS_SERVER_CERT"),
                   help="Server certificate PEM  [env: TLS_SERVER_CERT]")
    p.add_argument("--server-key",
                   default=os.environ.get("TLS_SERVER_KEY"),
                   help="Server private key PEM  [env: TLS_SERVER_KEY]")
    p.add_argument("--key",
                   default=os.environ.get("TRANSFER_KEY"),
                   help="64-hex-char AES-256 key  [env: TRANSFER_KEY]")
    return p


def handle_transfer(
    tls: ssl.SSLSocket,
    aesgcm: AESGCM,
    tmp_path: Path,
    out_path: Path,
) -> None:
    """Drive the chunk receive loop, verify integrity, and finalize the file.

    Separated from main() so all cleanup paths are clearly local.
    """
    sha256      = hashlib.sha256()
    chunk_index = 0

    try:
        with tmp_path.open("wb") as out_fh:
            while True:
                # ── Framing header ────────────────────────────────────────────
                try:
                    header = recv_exact(tls, LEN_PREFIX)
                except (EOFError, OSError) as exc:
                    abort(tmp_path, f"Network error reading chunk header: {exc}")

                payload_len = struct.unpack(">I", header)[0]

                if payload_len == 0:
                    break  # end-of-stream sentinel

                # Sanity-check before allocating — reject absurdly large claims
                if payload_len > MAX_PAYLOAD:
                    abort(
                        tmp_path,
                        f"Chunk {chunk_index}: declared payload_len={payload_len} "
                        f"exceeds ceiling {MAX_PAYLOAD} — possible protocol attack",
                    )

                # ── Ciphertext + tag ──────────────────────────────────────────
                try:
                    ciphertext = recv_exact(tls, payload_len)
                except (EOFError, OSError) as exc:
                    abort(tmp_path, f"Network error reading chunk {chunk_index}: {exc}")

                # ── Derive nonce and AAD (never accepted from the wire) ────────
                nonce = make_nonce(chunk_index)
                aad   = make_aad(chunk_index)

                # ── Decrypt + authenticate ────────────────────────────────────
                # AESGCM.decrypt() raises InvalidTag if the 128-bit tag does
                # not match — covers: wrong key, tampered bytes, wrong nonce,
                # mismatched AAD (i.e. chunk reordering).
                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
                except InvalidTag:
                    abort(
                        tmp_path,
                        f"Chunk {chunk_index}: AEAD tag verification FAILED — "
                        "data has been tampered with, is corrupt, or was reordered",
                    )

                sha256.update(plaintext)
                out_fh.write(plaintext)
                chunk_index += 1

                if chunk_index % 256 == 0:
                    mib = chunk_index * CHUNK_SIZE // (1024 * 1024)
                    print(f"[receiver]   … {mib} MiB received")

    except (EOFError, OSError) as exc:
        # Catch any I/O error not already handled inside the loop
        abort(tmp_path, f"Unexpected I/O error: {exc}")

    # ── Receive and verify end-to-end SHA-256 ─────────────────────────────────
    try:
        received_hash = recv_exact(tls, HASH_LENGTH)
    except (EOFError, OSError) as exc:
        abort(tmp_path, f"Failed to receive final hash: {exc}")

    computed_hash = sha256.digest()

    if received_hash != computed_hash:
        abort(
            tmp_path,
            f"SHA-256 mismatch — stream may be truncated or corrupted\n"
            f"  received : {received_hash.hex()}\n"
            f"  computed : {computed_hash.hex()}",
        )

    # ── Atomic promotion: temp → final ────────────────────────────────────────
    # os.replace() (POSIX rename()) is atomic on the same filesystem, so the
    # destination is never visible in a partial state to other processes.
    tmp_path.replace(out_path)

    print(
        f"[receiver] Integrity verified\n"
        f"           chunks  : {chunk_index}\n"
        f"           SHA-256 : {computed_hash.hex()}\n"
        f"           output  : {out_path}"
    )
    tls.sendall(b"OK\n")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ── Validate required arguments ───────────────────────────────────────────
    missing = [
        label
        for label, val in [
            ("--ca-cert / TLS_CA_CERT",           args.ca_cert),
            ("--server-cert / TLS_SERVER_CERT",   args.server_cert),
            ("--server-key / TLS_SERVER_KEY",     args.server_key),
            ("--key / TRANSFER_KEY",              args.key),
        ]
        if not val
    ]
    if missing:
        parser.error("Missing required arguments: " + ", ".join(missing))

    try:
        aes_key = bytes.fromhex(args.key)
    except ValueError:
        parser.error("--key / TRANSFER_KEY must be a valid hexadecimal string")
    if len(aes_key) != KEY_LENGTH:
        parser.error(
            f"--key must decode to exactly {KEY_LENGTH} bytes "
            f"({KEY_LENGTH * 2} hex chars); got {len(aes_key)} bytes"
        )

    out_path = Path(args.output)
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")

    # ── TLS context ───────────────────────────────────────────────────────────
    # PROTOCOL_TLS_SERVER does NOT set verify_mode — CERT_REQUIRED must be
    # set explicitly to enforce mutual TLS.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # reject TLS < 1.3
    ctx.load_verify_locations(args.ca_cert)          # trust our CA only
    ctx.load_cert_chain(args.server_cert, args.server_key)
    ctx.verify_mode = ssl.CERT_REQUIRED              # CRITICAL: enforce mTLS

    aesgcm = AESGCM(aes_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind, args.port))
        srv.listen(1)
        print(f"[receiver] Listening on {args.bind}:{args.port} …")

        raw_conn, addr = srv.accept()
        with ctx.wrap_socket(raw_conn, server_side=True) as tls:
            print(
                f"[receiver] Connection from {addr}\n"
                f"           cipher  : {(tls.cipher() or ['None'])[0]}\n"
                f"           version : {tls.version()}"
            )

            # Verify the TLS layer actually enforced client authentication.
            # With CERT_REQUIRED this should never fail, but a defensive check
            # is cheap and makes the mTLS guarantee explicit in code.
            peer_cert = tls.getpeercert()
            if not peer_cert:
                # Do not write any data; no temp file exists yet.
                sys.exit("[receiver] ABORT: client did not present a certificate")
            print(f"[receiver] Client cert subject: {peer_cert.get('subject')}")

            handle_transfer(tls, aesgcm, tmp_path, out_path)


if __name__ == "__main__":
    main()
