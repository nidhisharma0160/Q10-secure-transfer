# DESIGN.md — Approach A: Mutually-Authenticated TLS Streaming

## 1. Architecture Overview

```
SENDER                                          RECEIVER
──────                                          ────────

  [File on disk]                              [.tmp file on disk]
       │                                              │
       │ read 1 MiB at a time                         │ write plaintext
       ▼                                              ▼
  ┌─────────────┐    TLS 1.3 record layer    ┌─────────────────┐
  │  AES-256-GCM│ ─── [len][ciphertext+tag]─▶│  AES-256-GCM    │
  │  encrypt    │                            │  decrypt        │
  │  (per chunk)│                            │  (per chunk)    │
  └─────────────┘                            └─────────────────┘
       │                                              │
       │ [4-byte 0x00] end sentinel                   │
       │ [32-byte SHA-256 of plaintext]               │ verify SHA-256
       │ ◀─────────────── b"OK\n" ACK ───────────────▶│
       │                                              │
  [client.crt]                                  [server.crt]
  [client.key]   ◀── mTLS handshake (mutual) ──▶[server.crt]
  [ca.crt]            X.509, TLS 1.3             [ca.crt]


PKI layout
──────────
  ca.key / ca.crt          Self-signed CA (signs both leaf certs)
  server.key / server.crt  Receiver identity  (SAN: IP:127.0.0.1, DNS:localhost)
  client.key / client.crt  Sender identity    (extendedKeyUsage: clientAuth)
```

**Architectural category:** Transport-layer security with online ephemeral key exchange (ECDHE inside TLS 1.3) plus application-layer AEAD per-chunk as defence-in-depth.

---

## 2. Key Exchange and Key Management

| Item | Detail |
|------|--------|
| **Session key exchange** | TLS 1.3 with ECDHE. Ephemeral Diffie-Hellman keys are generated fresh for every connection; no long-lived session key is ever stored or transmitted. |
| **Forward secrecy** | Provided by TLS 1.3 ECDHE. Compromise of the long-lived private keys (server.key / client.key) does NOT retroactively expose any recorded session because each session's traffic keys are derived from discarded ephemeral DH values. |
| **Mutual authentication** | Both sides present an X.509 certificate signed by the shared CA. The sender sets `CERT_REQUIRED` on the TLS context; the receiver enforces `ctx.verify_mode = ssl.CERT_REQUIRED` explicitly (not relying on the default). |
| **Application-layer AES-256 key** | A separate 32-byte AES-256 key (`TRANSFER_KEY`) is shared out-of-band (e.g., via `secrets.token_hex(32)` and a secure side-channel). It is read from an environment variable or CLI flag — never hardcoded in source. |
| **Why a second key above TLS?** | TLS already encrypts the channel. The per-chunk AES-GCM layer is defence-in-depth: it ensures chunk-level authentication independent of the TLS library, protects against a future TLS implementation bug that leaks plaintext, and binds each chunk to its position via AAD. |
| **Nonce derivation** | Counter-based: `nonce = chunk_index.to_bytes(12, "big")`. Counter nonces are collision-free (2^96 − 1 possible values vs ≤ 4,096 chunks for a 4 GiB file at 1 MiB/chunk). The nonce is **not transmitted** — both sides derive it independently from their counters. |

---

## 3. Chunking and Framing

```
┌─────────────────────────────────────────────────────────────┐
│  Per-chunk wire frame (inside TLS record)                   │
│                                                             │
│  ┌──────────┬──────────────────────────────────────────┐   │
│  │ 4 bytes  │  N bytes                                 │   │
│  │ BE uint32│  AES-256-GCM ciphertext || 16-byte tag   │   │
│  │ payload  │                                          │   │
│  │ length   │  N = plaintext_len + 16 (GCM tag)        │   │
│  └──────────┴──────────────────────────────────────────┘   │
│                                                             │
│  AEAD inputs:                                               │
│    key    = TRANSFER_KEY (32 bytes, shared out-of-band)     │
│    nonce  = chunk_index as 96-bit big-endian (12 bytes)     │
│    aad    = chunk_index as 64-bit big-endian (8 bytes)      │
│    plain  = up to 1,048,576 bytes (1 MiB)                  │
└─────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────┐
│  End-of-stream sequence (after last chunk)            │
│                                                       │
│  [4 bytes: 0x00000000]  ← sentinel (zero payload)    │
│  [32 bytes: SHA-256 of concatenated plaintext]        │
│  ← receiver sends b"OK\n" if all checks pass          │
└───────────────────────────────────────────────────────┘
```

**Chunk size:** 1 MiB (1,048,576 bytes) — constant `CHUNK_SIZE = 1024 * 1024`.  
Chosen as a balance between memory pressure (file never fully in RAM), per-chunk overhead (16-byte tag + 4-byte length prefix = 20 bytes per 1 MiB → 0.002% overhead), and syscall frequency.

**Receiver safety:** Before allocating memory for a chunk, the receiver checks `payload_len <= MAX_PAYLOAD (CHUNK_SIZE + TAG_LENGTH)`. A malicious oversized length prefix is rejected before any allocation occurs.

---

## 4. Exact Algorithms and Parameters

| Parameter | Value | Justification |
|-----------|-------|---------------|
| **TLS version** | TLS 1.3 (minimum enforced via `ctx.minimum_version = ssl.TLSVersion.TLSv1_3`) | TLS 1.2 has known weaknesses (BEAST, POODLE variants). 1.3 removes them and always uses ECDHE. |
| **TLS cipher suites** | Negotiated by TLS 1.3 (AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256, AES-128-GCM-SHA256) | Python's ssl module restricts to AEAD-only suites in TLS 1.3 by design. |
| **Application cipher** | AES-256-GCM | AEAD — provides confidentiality + integrity + authenticity in one primitive. Approved by NIST SP 800-38D. |
| **Key length** | 256 bits (32 bytes) | AES-256 provides 128-bit security margin against exhaustive search. |
| **GCM nonce** | 96 bits (12 bytes), counter-derived | NIST SP 800-38D §8.2 recommends 96-bit nonces for GCM. Counter derivation eliminates random nonce collision risk. |
| **GCM tag** | 128 bits (16 bytes) — never truncated | Full-length tag. Truncation weakens forgery resistance exponentially. |
| **AAD** | `chunk_index` as 64-bit big-endian | Binds each ciphertext to its position; prevents reordering without decryption failure. |
| **End-to-end hash** | SHA-256 of concatenated plaintext | Detects truncation and any integrity failure the AEAD layer might miss (e.g., dropped final chunk before sentinel). |
| **Certificate signature** | RSA-4096 with SHA-256 | 4096-bit RSA provides >128-bit security. SHA-256 for signing. |
| **Crypto library** | `cryptography` (PyCA) — `cryptography.hazmat.primitives.ciphers.aead.AESGCM` | Well-reviewed, widely audited. No hand-rolled primitives. |

---

## 5. Threat Model — Row-by-Row Response

| Threat | CIAA Bucket | Mechanism in This Design | Evidence in Code |
|--------|-------------|--------------------------|-----------------|
| **Passive eavesdropper records the entire TCP stream** | Confidentiality | All bytes on the wire are TLS 1.3 records. An eavesdropper sees only ciphertext negotiated via ECDHE — the traffic key is never transmitted and cannot be derived without the private DH value, which is ephemeral and discarded after the handshake. The application-layer AES-256-GCM layer provides a second encryption envelope even if TLS were stripped. | `ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` + `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` in sender.py; `aesgcm.encrypt(nonce, plaintext, aad)` per chunk. |
| **Active MITM modifies bytes mid-flight** | Integrity | Each 1 MiB chunk is protected by a 128-bit AES-GCM authentication tag. Any single-bit flip in the ciphertext causes `AESGCM.decrypt()` to raise `InvalidTag`. The receiver calls `abort()` immediately: the `.tmp` file is deleted and the process exits non-zero. The SHA-256 of the entire plaintext is sent after all chunks and verified before the final rename — catching truncation or a dropped chunk. | `except InvalidTag: abort(tmp_path, …)` in receiver.py lines 197-201; `if received_hash != computed_hash: abort(…)` lines 223-229. |
| **Attacker spoofs the sender or receiver** | Authenticity | Both endpoints must present a valid X.509 certificate signed by the shared CA. The receiver sets `ctx.verify_mode = ssl.CERT_REQUIRED` — the TLS handshake fails closed if no client cert is presented or if it is not signed by the trusted CA. The sender uses `PROTOCOL_TLS_CLIENT` which enforces server cert verification and hostname checking by default. An attacker without the CA-signed private key cannot complete the handshake. | `ctx.verify_mode = ssl.CERT_REQUIRED` in receiver.py line 283; `ctx.load_verify_locations(args.ca_cert)` on both sides; defensive `if not peer_cert: sys.exit(…)` in receiver.py line 307. |
| **Replay of an earlier valid transfer** | Integrity / Authenticity | TLS 1.3 includes a fresh ECDHE handshake per session, producing unique per-session traffic keys. Even a byte-for-byte replay of a captured TLS session would be rejected at the TLS record layer because the session keys are different. At the application layer, the counter-based nonces mean the AES-GCM ciphertext of the same plaintext differs each session (because the traffic key changes). The SHA-256 hash travels inside TLS and cannot be precomputed or replayed independently. | `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` enforces 1-RTT with fresh ephemeral keys per connection. Nonce = `chunk_index.to_bytes(12, "big")` derived per-session from the session key. |
| **Connection drops at 80% transferred** | Availability | The receiver writes all data to `<output>.tmp`, not to the final filename. If the connection drops (raising `EOFError` or `OSError`), the `abort()` helper deletes the `.tmp` file and exits non-zero. The final filename is only written atomically via `tmp_path.replace(out_path)` (POSIX `rename()`) after both the AEAD tag on the last chunk and the SHA-256 final hash are verified. A partial transfer is therefore never visible under the final name. The sender can be re-run to restart the transfer from zero. | `tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")` in receiver.py line 274; `tmp_path.replace(out_path)` line 234; `abort(tmp_path, …)` on all error paths. |
| **Untrusted intermediary (broker / object store)** | Confidentiality / Integrity | Not applicable to this approach. Approach A is a direct sender-to-receiver TCP stream with no broker or storage tier. There is no intermediary that could observe plaintext or hold ciphertext for later injection. This threat is addressed in Approach B. | N/A — direct TCP socket between sender and receiver. |

---

## 6. Known Limitations and Trade-offs

- **No true resumability.** If the connection drops, the receiver deletes its `.tmp` file and the transfer must restart from byte 0. True resume (picking up at the last verified chunk) would require a persistent chunk-offset log on the receiver side, which is a stretch goal.
- **Single connection.** The receiver accepts one connection then exits. Production use would require a loop or a process-per-connection model.
- **Self-signed CA.** Acceptable per the assignment scope. The CA private key (`ca.key`) must be protected; compromise of it allows issuance of fraudulent sender/receiver certs.
- **Key rotation.** The TRANSFER_KEY is static for the lifetime of the key file. Rotating it requires re-sharing out-of-band.
