#!/usr/bin/env python3
"""
Approach A — Mutually-authenticated TLS sender.

Connects to the receiver over TLS 1.3 (with mutual certificate authentication),
then streams a file in 1 MiB chunks.  Each chunk is encrypted in-place with
AES-256-GCM; the nonce is derived from a counter so it is unique per chunk and
never requires random generation or wire transmission.  After the last chunk an
end-of-stream sentinel is sent, followed by a SHA-256 hash of the full plaintext
for end-to-end integrity verification.

Wire protocol (all sent inside the TLS record layer):
    Per chunk  : [4-byte BE payload_len] [AES-GCM ciphertext || 16-byte tag]
    End marker : [4-byte BE: 0x00000000]
    Final hash : [32-byte SHA-256 of concatenated plaintext chunks]
    ACK        : receiver sends b"OK\\n" on success

Security notes
--------------
* Nonce = chunk_index encoded as 96-bit big-endian integer.
  Counter-based nonces guarantee uniqueness without random generation.
  The nonce is NOT transmitted; both sides derive it from their counters.
* AAD    = chunk_index encoded as 64-bit big-endian integer.
  Binding ciphertext to its ordinal position defeats chunk-reorder replay.
* AES-GCM authentication tag is always 128 bits (16 bytes) — never truncated.
* TLS 1.3 provides forward secrecy, mutual authentication, and its own
  replay protection; AES-GCM is a defence-in-depth layer above it.
* The SHA-256 hash travels inside TLS, so it cannot be replaced by a MITM.

Usage
-----
    python sender.py [options] <file>

Required (env var or CLI flag):
    TRANSFER_KEY          64-hex-char AES-256 key  (32 bytes)
    TLS_CA_CERT           path to CA certificate PEM
    TLS_CLIENT_CERT       path to client certificate PEM
    TLS_CLIENT_KEY        path to client private key PEM
"""

import argparse
import hashlib
import os
import socket
import ssl
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Named constants ───────────────────────────────────────────────────────────
CHUNK_SIZE   = 1024 * 1024  # 1 MiB per chunk
KEY_LENGTH   = 32           # AES-256 → 32 bytes
NONCE_LENGTH = 12           # 96-bit GCM nonce (NIST SP 800-38D §8.2)
TAG_LENGTH   = 16           # 128-bit GCM authentication tag (never truncate)
HASH_LENGTH  = 32           # SHA-256 output length in bytes
LEN_PREFIX   = 4            # bytes reserved for the chunk-length framing header


# ── Nonce / AAD derivation ────────────────────────────────────────────────────

def make_nonce(chunk_index: int) -> bytes:
    """Return the unique 96-bit nonce for *chunk_index*.

    Counter nonces are collision-free for any realistic number of chunks.
    For a 4 GiB file at 1 MiB/chunk there are at most 4 096 chunks; the
    96-bit counter space holds 2^96 − 1 ≈ 7.9 × 10^28 values before wrap.
    The nonce is derived independently on both sides, so it is never sent
    over the wire — this eliminates one class of injection attack.
    """
    return chunk_index.to_bytes(NONCE_LENGTH, byteorder="big")


def make_aad(chunk_index: int) -> bytes:
    """Return the 64-bit AAD for *chunk_index*.

    Including the chunk position in AAD means a valid ciphertext cannot be
    silently moved to a different slot: decryption will fail because the AAD
    no longer matches what was authenticated at encrypt time.
    """
    return chunk_index.to_bytes(8, byteorder="big")


# ── I/O helpers ───────────────────────────────────────────────────────────────

def send_all(sock: ssl.SSLSocket, data: bytes) -> None:
    """Write *data* in full, retrying on short sends."""
    mv = memoryview(data)
    sent = 0
    while sent < len(mv):
        n = sock.send(mv[sent:])
        if n == 0:
            raise BrokenPipeError("Connection closed during send")
        sent += n


def recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, retrying on short reads."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(
                f"Connection closed after {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


# ── Main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="mTLS AES-256-GCM streaming file sender (Approach A)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("file", help="Path to the file to transfer")
    p.add_argument("--host",        default="127.0.0.1",
                   help="Receiver hostname or IP (default: 127.0.0.1)")
    p.add_argument("--port",        type=int, default=9443,
                   help="Receiver TCP port (default: 9443)")
    p.add_argument("--server-name", default=None,
                   help="TLS SNI name sent to server (defaults to --host). "
                        "Must match the server certificate CN/SAN.")
    p.add_argument("--ca-cert",
                   default=os.environ.get("TLS_CA_CERT"),
                   help="CA certificate PEM  [env: TLS_CA_CERT]")
    p.add_argument("--client-cert",
                   default=os.environ.get("TLS_CLIENT_CERT"),
                   help="Client certificate PEM  [env: TLS_CLIENT_CERT]")
    p.add_argument("--client-key",
                   default=os.environ.get("TLS_CLIENT_KEY"),
                   help="Client private key PEM  [env: TLS_CLIENT_KEY]")
    p.add_argument("--key",
                   default=os.environ.get("TRANSFER_KEY"),
                   help="64-hex-char AES-256 key  [env: TRANSFER_KEY]")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ── Validate required arguments ───────────────────────────────────────────
    missing = [
        label
        for label, val in [
            ("--ca-cert / TLS_CA_CERT",          args.ca_cert),
            ("--client-cert / TLS_CLIENT_CERT",  args.client_cert),
            ("--client-key / TLS_CLIENT_KEY",    args.client_key),
            ("--key / TRANSFER_KEY",             args.key),
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

    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"[sender] Error: {str(src)!r} is not a regular file")

    server_name = args.server_name or args.host

    # ── TLS context ───────────────────────────────────────────────────────────
    # PROTOCOL_TLS_CLIENT enables certificate verification and hostname
    # checking by default — both are required for mTLS security.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # reject TLS < 1.3
    ctx.load_verify_locations(args.ca_cert)          # trust our CA only
    ctx.load_cert_chain(args.client_cert, args.client_key)  # present client cert
    # ctx.check_hostname = True  (already True with PROTOCOL_TLS_CLIENT)
    # ctx.verify_mode = ssl.CERT_REQUIRED  (already set)

    aesgcm = AESGCM(aes_key)
    sha256 = hashlib.sha256()

    print(f"[sender] Connecting to {args.host}:{args.port}  SNI={server_name} …")
    with socket.create_connection((args.host, args.port)) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=server_name) as tls:
            peer = tls.getpeercert()
            print(
                f"[sender] TLS handshake OK\n"
                f"         cipher  : {tls.cipher()[0]}\n"
                f"         version : {tls.version()}\n"
                f"         server  : {peer.get('subject')}"
            )

            chunk_index = 0

            # ── Stream file in 1 MiB chunks ───────────────────────────────────
            with src.open("rb") as fh:
                while True:
                    plaintext = fh.read(CHUNK_SIZE)
                    if not plaintext:
                        break  # EOF

                    sha256.update(plaintext)

                    nonce      = make_nonce(chunk_index)
                    aad        = make_aad(chunk_index)
                    # encrypt() returns ciphertext || 16-byte AEAD tag
                    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

                    # Wire format: [4-byte BE length][ciphertext+tag]
                    send_all(tls, struct.pack(">I", len(ciphertext)) + ciphertext)
                    chunk_index += 1

                    if chunk_index % 256 == 0:
                        mib_sent = chunk_index * CHUNK_SIZE // (1024 * 1024)
                        print(f"[sender]   … {mib_sent} MiB sent")

            # ── End-of-stream sentinel ────────────────────────────────────────
            send_all(tls, struct.pack(">I", 0))

            # ── Final plaintext SHA-256 (travels inside TLS — authenticated) ──
            digest = sha256.digest()
            send_all(tls, digest)
            print(
                f"[sender] Transfer complete\n"
                f"         chunks  : {chunk_index}\n"
                f"         SHA-256 : {digest.hex()}"
            )

            # ── Wait for receiver ACK ─────────────────────────────────────────
            ack = recv_exact(tls, 3)
            if ack == b"OK\n":
                print("[sender] Receiver confirmed integrity. Done.")
            else:
                sys.exit(f"[sender] Error: unexpected ACK from receiver: {ack!r}")


if __name__ == "__main__":
    main()
