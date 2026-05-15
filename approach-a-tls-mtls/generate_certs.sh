#!/usr/bin/env bash
# generate_certs.sh
#
# Creates a minimal PKI for testing the Approach-A mTLS file transfer:
#   - Self-signed CA  (signs both server and client certs)
#   - Server cert     (SAN: IP:127.0.0.1, DNS:localhost)
#   - Client cert     (extendedKeyUsage: clientAuth)
#
# Requirements: OpenSSL 1.1.1+ (for TLS 1.3 support and -addext flag).
#               Bash 4+ (for process-substitution in -extfile <(...)).
#
# Output layout:
#   certs/
#     ca.key        CA private key         *** KEEP SECRET ***
#     ca.crt        Self-signed CA certificate
#     ca.srl        CA serial number file (auto-created on first signing)
#     server.key    Server private key     *** KEEP SECRET ***
#     server.crt    Server certificate (signed by CA)
#     client.key    Client private key     *** KEEP SECRET ***
#     client.crt    Client certificate (signed by CA)
#
# Usage:
#   chmod +x generate_certs.sh && ./generate_certs.sh
#
# After running, export a transfer key and start sender/receiver:
#   export TRANSFER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
#
#   # Terminal 1 — receiver:
#   TLS_CA_CERT=certs/ca.crt \
#   TLS_SERVER_CERT=certs/server.crt \
#   TLS_SERVER_KEY=certs/server.key \
#   python receiver.py received_output.bin
#
#   # Terminal 2 — sender:
#   TLS_CA_CERT=certs/ca.crt \
#   TLS_CLIENT_CERT=certs/client.crt \
#   TLS_CLIENT_KEY=certs/client.key \
#   python sender.py /path/to/your/4GB.bin

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
CERTS_DIR="${CERTS_DIR:-certs}"
DAYS="${DAYS:-365}"
KEY_BITS="${KEY_BITS:-4096}"          # 4096-bit RSA; use 2048 for faster testing
DIGEST="-sha256"
SUBJ_BASE="/C=US/ST=TestState/L=TestCity/O=SecureTransfer"

# Server SAN: adjust if connecting to a hostname other than 127.0.0.1/localhost
SERVER_SAN="IP:127.0.0.1,DNS:localhost"

mkdir -p "$CERTS_DIR"

echo "=== Generating PKI in ./$CERTS_DIR/ (KEY_BITS=$KEY_BITS, DAYS=$DAYS) ==="
echo ""

# ── Step 1: CA private key ────────────────────────────────────────────────────
echo "[1/6] Generating CA private key …"
openssl genrsa \
    -out "$CERTS_DIR/ca.key" \
    "$KEY_BITS" 2>/dev/null
echo "      → $CERTS_DIR/ca.key"

# ── Step 2: Self-signed CA certificate ───────────────────────────────────────
echo "[2/6] Creating self-signed CA certificate …"
openssl req -new -x509 "$DIGEST" \
    -key  "$CERTS_DIR/ca.key" \
    -out  "$CERTS_DIR/ca.crt" \
    -days "$DAYS" \
    -subj "$SUBJ_BASE/CN=TransferCA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
echo "      → $CERTS_DIR/ca.crt"

# ── Step 3: Server private key ────────────────────────────────────────────────
echo "[3/6] Generating server private key …"
openssl genrsa \
    -out "$CERTS_DIR/server.key" \
    "$KEY_BITS" 2>/dev/null
echo "      → $CERTS_DIR/server.key"

# ── Step 4: Server certificate (signed by CA) ────────────────────────────────
echo "[4/6] Creating and signing server certificate …"
#
# The SAN extension is *required* for Python's ssl module to accept the cert
# when check_hostname=True (the PROTOCOL_TLS_CLIENT default).
# Without a SAN the handshake will fail with a hostname-mismatch error.
#
SERVER_EXT="subjectAltName=${SERVER_SAN}
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash"

openssl req -new "$DIGEST" \
    -key  "$CERTS_DIR/server.key" \
    -subj "$SUBJ_BASE/CN=localhost" \
| openssl x509 -req "$DIGEST" \
    -CA           "$CERTS_DIR/ca.crt" \
    -CAkey        "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out          "$CERTS_DIR/server.crt" \
    -days         "$DAYS" \
    -extfile      <(printf '%s\n' "$SERVER_EXT")
echo "      → $CERTS_DIR/server.crt  (SAN: $SERVER_SAN)"

# ── Step 5: Client private key ────────────────────────────────────────────────
echo "[5/6] Generating client private key …"
openssl genrsa \
    -out "$CERTS_DIR/client.key" \
    "$KEY_BITS" 2>/dev/null
echo "      → $CERTS_DIR/client.key"

# ── Step 6: Client certificate (signed by CA) ────────────────────────────────
echo "[6/6] Creating and signing client certificate …"
CLIENT_EXT="basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash"

openssl req -new "$DIGEST" \
    -key  "$CERTS_DIR/client.key" \
    -subj "$SUBJ_BASE/CN=transfer-client" \
| openssl x509 -req "$DIGEST" \
    -CA           "$CERTS_DIR/ca.crt" \
    -CAkey        "$CERTS_DIR/ca.key" \
    -CAserial     "$CERTS_DIR/ca.srl" \
    -out          "$CERTS_DIR/client.crt" \
    -days         "$DAYS" \
    -extfile      <(printf '%s\n' "$CLIENT_EXT")
echo "      → $CERTS_DIR/client.crt"

# ── Restrict private key permissions ─────────────────────────────────────────
chmod 600 "$CERTS_DIR"/*.key
echo ""
echo "Private key permissions set to 600."

# ── Quick verification ────────────────────────────────────────────────────────
echo ""
echo "=== Verification ==="
echo "Server cert chain:"
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/server.crt"
echo "Client cert chain:"
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/client.crt"
echo "Server SAN:"
openssl x509 -noout -ext subjectAltName -in "$CERTS_DIR/server.crt"

# ── Quick-start instructions ─────────────────────────────────────────────────
cat <<'EOF'

=== Quick Start ===

  # 1. Generate a random 32-byte (256-bit) AES key:
  export TRANSFER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  echo "TRANSFER_KEY=$TRANSFER_KEY"   # save this — both sides need it

  # 2. Install the Python dependency (if not already installed):
  pip install cryptography

  # 3. Start the receiver (Terminal 1):
  TLS_CA_CERT=certs/ca.crt \
  TLS_SERVER_CERT=certs/server.crt \
  TLS_SERVER_KEY=certs/server.key \
  python receiver.py received_output.bin

  # 4. Send a file (Terminal 2 — set TRANSFER_KEY first):
  TLS_CA_CERT=certs/ca.crt \
  TLS_CLIENT_CERT=certs/client.crt \
  TLS_CLIENT_KEY=certs/client.key \
  python sender.py /path/to/4GB_file.bin

  # To test with a synthetic 4 GiB file:
  dd if=/dev/urandom of=/tmp/test4gb.bin bs=1M count=4096

  # 5. Verify the received file matches the original:
  sha256sum /tmp/test4gb.bin received_output.bin

Notes
-----
* These are self-signed development certificates — NOT for production use.
* To transfer to a different host, regenerate with the server's IP/hostname
  in SERVER_SAN (e.g.  SERVER_SAN="IP:10.0.1.5,DNS:fileserver.example.com")
  and pass --server-name to sender.py to match the cert CN/SAN.
* Key lifetime: $DAYS days from generation.  Regenerate before expiry.
EOF
