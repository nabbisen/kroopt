#!/usr/bin/env bash
# gen-test-cert.sh — provision the test server certificate kroopt presents.
#
# Builds a self-signed Ed25519 X.509 certificate whose subject public key is
# kroopt's certificate key (the RFC 8032 §7.1 Test 1 key, also used for the
# CertificateVerify signature). The DER is embedded as `certDer` in
# Tests/RealHandshake.lean so the live handshake presents a real, parseable
# certificate. Re-running produces a fresh serial/SKI/validity window; the
# embedded fixture is one such cert.
set -euo pipefail
SEED="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 - "$SEED" "$TMP/key.pem" << 'PY'
import base64, sys
seed = bytes.fromhex(sys.argv[1])
pkcs8 = bytes.fromhex("302e020100300506032b657004220420") + seed   # RFC 8410 Ed25519 PKCS8
open(sys.argv[2], "w").write(
    "-----BEGIN PRIVATE KEY-----\n"
    + base64.encodebytes(pkcs8).decode().strip()
    + "\n-----END PRIVATE KEY-----\n")
PY
openssl req -new -x509 -key "$TMP/key.pem" -days 36500 -subj "/CN=kroopt.test" \
  -addext "subjectAltName=DNS:kroopt.test" -outform DER -out "$TMP/cert.der"
echo "== certificate =="
openssl x509 -in "$TMP/cert.der" -inform DER -noout -subject -issuer
echo "bytes: $(wc -c < "$TMP/cert.der")"
echo "== DER hex (embed as certDer) =="
python3 -c "print(open('$TMP/cert.der','rb').read().hex())"
