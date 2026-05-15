# Secure 4 GB File Transfer — Two Approaches

Security Engineering Assessment — AI-Assisted Coding Challenge

Two architecturally distinct implementations that securely transfer a 4 GB file over an untrusted public network, satisfying **CIAA** (Confidentiality, Integrity, Authenticity, Availability) end-to-end.

| | Approach A | Approach B |
|---|---|---|
| **Directory** | `approach-a-tls-mtls/` | `approach-b-encrypted-envelope/` |
| **Transport security** | TLS 1.3 (transport layer) | Plain TCP (application layer only) |
| **Key exchange** | Online ECDHE via mTLS handshake | Pre-distributed 32-byte PSK (out-of-band) |
| **Authentication** | Mutual X.509 certificates | HMAC-SHA256 signed manifest |
| **Per-chunk crypto** | AES-256-GCM, counter nonce | AES-256-GCM, random nonce |
| **Forward secrecy** | Yes (TLS 1.3 ECDHE) | No (static PSK) |

---

## Prerequisites

- Python 3.11 or later
- OpenSSL 1.1.1 or later (for `generate_certs.sh` in Approach A)
- pip

Install the single Python dependency:

```bash
pip install cryptography
```

---

## Generating the 4 GB Test File

**Do not commit this file.** Generate it locally before running either approach.

```bash
# macOS / Linux — using dd
dd if=/dev/urandom of=test_4gb.bin bs=1M count=4096

# Cross-platform Python alternative
python3 -c "open('test_4gb.bin','wb').write(b'\x00' * 4 * 1024 * 1024 * 1024)"
```

Record the SHA-256 hash before sending — you will compare it against the received file afterward:

```bash
# macOS
shasum -a 256 test_4gb.bin

# Linux
sha256sum test_4gb.bin
```

---

## Approach A — Mutually-Authenticated TLS Streaming

**Architecture:** Both sides hold X.509 certificates signed by a shared CA. A TLS 1.3 handshake with mutual certificate verification secures the channel. Each 1 MiB chunk is also encrypted with AES-256-GCM as defence-in-depth. A SHA-256 hash of the full plaintext is verified before the received file is written to its final name.

### Step 1 — Generate certificates

```bash
cd approach-a-tls-mtls/
chmod +x generate_certs.sh
./generate_certs.sh
```

This creates `certs/ca.crt`, `certs/server.crt`, `certs/server.key`, `certs/client.crt`, `certs/client.key`.

### Step 2 — Generate the AES-256 transfer key

```bash
export TRANSFER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
echo "TRANSFER_KEY=$TRANSFER_KEY"   # save this — both terminals need it
```

### Step 3 — Start the receiver (Terminal 1)

```bash
cd approach-a-tls-mtls/

TLS_CA_CERT=certs/ca.crt \
TLS_SERVER_CERT=certs/server.crt \
TLS_SERVER_KEY=certs/server.key \
TRANSFER_KEY=$TRANSFER_KEY \
python3 receiver.py received_output.bin
```

The receiver prints `Listening on 0.0.0.0:9443 …` and waits.

### Step 4 — Run the sender (Terminal 2)

```bash
cd approach-a-tls-mtls/

TLS_CA_CERT=certs/ca.crt \
TLS_CLIENT_CERT=certs/client.crt \
TLS_CLIENT_KEY=certs/client.key \
TRANSFER_KEY=$TRANSFER_KEY \
python3 sender.py ../test_4gb.bin
```

### Step 5 — Verify the hash

```bash
# macOS
shasum -a 256 ../test_4gb.bin received_output.bin

# Linux
sha256sum ../test_4gb.bin received_output.bin
```

Both lines must show the same hash. The receiver also prints the SHA-256 on success.

---

## Approach B — Encrypted Envelope over Plain TCP

**Architecture:** No TLS. A 32-byte pre-shared key (PSK) is distributed out-of-band. Each 1 MiB chunk is encrypted with AES-256-GCM using a fresh random nonce. After all chunks, a signed manifest (HMAC-SHA256) covering the file hash, chunk count, and timestamp is sent and verified. The receiver writes to a `.tmp` file and renames it atomically only after all checks pass.

### Step 1 — Generate the pre-shared key

```bash
cd approach-b-encrypted-envelope/
python3 generate_key.py envelope.key
```

This writes 32 random bytes to `envelope.key` with mode `0600`. Copy this file to the receiver side before starting the transfer. **Never commit this file.**

### Step 2 — Start the receiver (Terminal 1)

```bash
cd approach-b-encrypted-envelope/

python3 receiver.py \
  --key-file envelope.key \
  --output-dir received/
```

The receiver prints `Listening on 0.0.0.0:9876 …` and waits.

### Step 3 — Run the sender (Terminal 2)

```bash
cd approach-b-encrypted-envelope/

python3 sender.py ../test_4gb.bin \
  --key-file envelope.key
```

### Step 4 — Verify the hash

```bash
# macOS
shasum -a 256 ../test_4gb.bin received/test_4gb.bin

# Linux
sha256sum ../test_4gb.bin received/test_4gb.bin
```

Both lines must show the same hash. The receiver also prints the SHA-256 on success.

---

## Failure / Tamper Tests

Run these to verify that both implementations fail loudly and clean up correctly.

### Test 1 — Tampered ciphertext (Integrity)

After a successful transfer, flip one byte in the received `.tmp` file mid-transfer by running the sender but intercepting a chunk. A simpler method: capture a chunk frame, flip a byte, and replay it. Both receivers will print an `AEAD tag verification FAILED` error, delete the `.tmp` file, and exit with code 1. The final output file will not exist.

Quick local test — corrupt a file that would be sent, observe the receiver abort:

```bash
# Create a small corrupted copy
cp test_4gb.bin test_corrupted.bin
python3 -c "
f = open('test_corrupted.bin', 'r+b')
f.seek(1024 * 1024 + 5)   # into the second chunk
f.write(b'\xff')
f.close()
"

# Run Approach A with the corrupted file — receiver should abort
TLS_CA_CERT=certs/ca.crt TLS_CLIENT_CERT=certs/client.crt \
TLS_CLIENT_KEY=certs/client.key TRANSFER_KEY=$TRANSFER_KEY \
python3 approach-a-tls-mtls/sender.py test_corrupted.bin
```

Expected receiver output: `ABORT: Chunk 1: AEAD tag verification FAILED`

### Test 2 — Wrong certificate (Authenticity) — Approach A

Start the Approach A receiver. Then attempt to connect with a certificate that was not signed by the trusted CA (e.g., generate a fresh self-signed cert):

```bash
# Generate an untrusted client cert
openssl req -x509 -newkey rsa:2048 -keyout bad_client.key \
  -out bad_client.crt -days 1 -nodes -subj "/CN=attacker"

# Attempt transfer with the wrong cert
TLS_CA_CERT=certs/ca.crt \
TLS_CLIENT_CERT=bad_client.crt \
TLS_CLIENT_KEY=bad_client.key \
TRANSFER_KEY=$TRANSFER_KEY \
python3 approach-a-tls-mtls/sender.py test_4gb.bin
```

Expected: TLS handshake fails with a certificate verification error. The receiver never accepts a connection. No data is transferred.

### Test 3 — Wrong key (Authenticity) — Approach B

Run Approach B receiver with the correct key. Run the sender with a different key file:

```bash
python3 approach-b-encrypted-envelope/generate_key.py wrong.key

python3 approach-b-encrypted-envelope/sender.py test_4gb.bin \
  --key-file wrong.key
```

Expected receiver output: `VERIFICATION FAILED — AES-GCM authentication tag invalid on chunk 0`. The `.tmp` file is deleted. Exit code 1.

### Test 4 — Connection drop mid-transfer (Availability)

Start a transfer and kill the sender process with Ctrl-C or `kill` after a few chunks. Check that the receiver's output directory does not contain the final file — only (briefly) a `.tmp` that gets deleted on abort.

```bash
# Terminal 1: start receiver
# Terminal 2: start sender, then Ctrl-C after ~10 seconds
# Terminal 3: confirm no final file and no .tmp remains
ls approach-b-encrypted-envelope/received/
```

Expected: directory is empty (or contains only previously completed transfers).

---

## Repository Structure

```
.
├── README.md                          ← this file
├── DESIGN_A.md                        ← Approach A design + threat model
├── DESIGN_B.md                        ← Approach B design + threat model
├── AI_NOTES.md                        ← AI usage reflection
├── approach-a-tls-mtls/
│   ├── sender.py                      ← mTLS AES-256-GCM sender
│   ├── receiver.py                    ← mTLS AES-256-GCM receiver
│   └── generate_certs.sh             ← generates CA, server, client certs
└── approach-b-encrypted-envelope/
    ├── sender.py                      ← PSK envelope sender
    ├── receiver.py                    ← PSK envelope receiver
    └── generate_key.py               ← generates 32-byte PSK file
```

**Not committed (add to .gitignore):**

```
test_4gb.bin
*.key
certs/
received/
*.tmp
```

---

## Design and Threat Model

See [`DESIGN_A.md`](DESIGN_A.md) and [`DESIGN_B.md`](DESIGN_B.md) for the full architecture diagrams, algorithm parameters, and row-by-row threat model responses covering: passive eavesdropper, active MITM, endpoint spoofing, replay attacks, mid-transfer connection drops, and untrusted intermediaries.
