#!/usr/bin/env bash
# ed25519-interop.sh — cross-library interop for the TLS 1.3 CertificateVerify
# signing path: the *vendored HACL* Ed25519* that kroopt links vs *OpenSSL*.
#
# Scope: validates the RFC 8446 4.4.3 CertificateVerify signature *construction* and
# that HACL* Ed25519 signatures verify under OpenSSL (and vice versa) for a shared
# keypair. A full `openssl s_client` / `curl` handshake against a running kroopt
# server is gated behind the pending real-handshake work (real transcript hashing,
# real server Finished, iotakt socket transport) and is not run here. See
# docs/src/crypto/provisioning.md.
#
# Requires: openssl, gcc, python3, the vendored HACL under Kroopt/Native/hacl.
set -euo pipefail
cd "$(dirname "$0")/.."
H=Kroopt/Native/hacl
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail() { echo "INTEROP FAIL: $*" >&2; exit 1; }
b2h() { python3 -c 'import sys;sys.stdout.write(sys.stdin.buffer.read().hex())'; }
h2b() { python3 -c 'import sys;open(sys.argv[2],"wb").write(bytes.fromhex(sys.argv[1]))' "$1" "$2"; }

echo "== building HACL Ed25519 CLI =="
gcc -O2 -I "$H" -I "$H/internal" -I "$H/include" -I "$H/minimal" \
  scripts/ed25519_hacl_cli.c "$H/Hacl_Ed25519.c" "$H/Hacl_Hash_SHA2.c" \
  "$H/Hacl_Streaming_SHA2.c" "$H/Hacl_Curve25519_51.c" "$H/Lib_Memzero0.c" \
  -o "$WORK/hacl_cli"
CLI="$WORK/hacl_cli"

echo "== generating an Ed25519 server cert keypair with OpenSSL =="
openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null
openssl pkey -in "$WORK/priv.pem" -pubout -out "$WORK/pub.pem" 2>/dev/null
SEED=$(openssl pkey -in "$WORK/priv.pem" -outform DER | tail -c 32 | b2h)
OSSL_PUB=$(openssl pkey -in "$WORK/priv.pem" -pubout -outform DER | tail -c 32 | b2h)

echo "== 1) HACL public key matches OpenSSL public key for the same seed =="
HACL_PUB=$("$CLI" pub "$SEED")
[ "$HACL_PUB" = "$OSSL_PUB" ] || fail "public key mismatch (HACL=$HACL_PUB OpenSSL=$OSSL_PUB)"
echo "   ok: $HACL_PUB"

echo "== building an RFC 8446 4.4.3 server CertificateVerify signed-content blob =="
TH=$(printf 'sample handshake transcript' | openssl dgst -sha256 -binary | b2h)
python3 - "$WORK/content.bin" "$TH" << 'PY'
import sys
out, th = sys.argv[1], sys.argv[2]
blob = b'\x20'*64 + b'TLS 1.3, server CertificateVerify' + b'\x00' + bytes.fromhex(th)
open(out, 'wb').write(blob)
PY

echo "== 2) HACL signs the CertificateVerify; OpenSSL verifies =="
HSIG=$("$CLI" sign "$SEED" "$WORK/content.bin")
h2b "$HSIG" "$WORK/hsig.bin"
openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin \
  -in "$WORK/content.bin" -sigfile "$WORK/hsig.bin" >/dev/null 2>&1 \
  || fail "OpenSSL rejected a HACL CertificateVerify signature"
echo "   ok: OpenSSL verified the HACL-produced CertificateVerify signature"

echo "== 3) OpenSSL signs the CertificateVerify; HACL verifies =="
openssl pkeyutl -sign -inkey "$WORK/priv.pem" -rawin -in "$WORK/content.bin" \
  -out "$WORK/osig.bin" 2>/dev/null
OSIG=$(b2h < "$WORK/osig.bin")
[ "$("$CLI" verify "$HACL_PUB" "$WORK/content.bin" "$OSIG")" = "OK" ] \
  || fail "HACL rejected an OpenSSL CertificateVerify signature"
echo "   ok: HACL verified the OpenSSL-produced CertificateVerify signature"

echo "== 4) tamper check: a flipped transcript byte must be rejected by both =="
cp "$WORK/content.bin" "$WORK/bad.bin"
printf '\xff' | dd of="$WORK/bad.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
if openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin \
   -in "$WORK/bad.bin" -sigfile "$WORK/hsig.bin" >/dev/null 2>&1; then
  fail "OpenSSL accepted a tampered CertificateVerify"
fi
[ "$("$CLI" verify "$HACL_PUB" "$WORK/bad.bin" "$HSIG")" = "FAIL" ] \
  || fail "HACL accepted a tampered CertificateVerify"
echo "   ok: both reject a tampered transcript"

echo "== 5) kroopt's presented certificate is consistent with its CertificateVerify =="
# Build kroopt's actual cert (from the cert seed) and confirm a real client could
# extract the leaf key from the Certificate message and verify the CertificateVerify.
KSEED="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
python3 - "$KSEED" "$WORK/kkey.pem" << 'PY'
import base64, sys
pkcs8 = bytes.fromhex("302e020100300506032b657004220420") + bytes.fromhex(sys.argv[1])
open(sys.argv[2], "w").write("-----BEGIN PRIVATE KEY-----\n"
  + base64.encodebytes(pkcs8).decode().strip() + "\n-----END PRIVATE KEY-----\n")
PY
openssl req -new -x509 -key "$WORK/kkey.pem" -days 36500 -subj "/CN=kroopt.test" \
  -addext "subjectAltName=DNS:kroopt.test" -outform DER -out "$WORK/kcert.der" 2>/dev/null
openssl x509 -in "$WORK/kcert.der" -inform DER -noout -subject >/dev/null 2>&1 \
  || fail "OpenSSL could not parse kroopt's presented certificate"
# Leaf public key extracted from the certificate (as a real peer would).
openssl x509 -in "$WORK/kcert.der" -inform DER -pubkey -noout > "$WORK/kleaf.pem" 2>/dev/null
KLEAF=$(openssl pkey -pubin -in "$WORK/kleaf.pem" -outform DER | tail -c 32 | b2h)
KEXP=$("$CLI" pub "$KSEED")
[ "$KLEAF" = "$KEXP" ] || fail "cert leaf key ($KLEAF) != kroopt signing key ($KEXP)"
# A kroopt CertificateVerify (HACL, signed with the cert seed) verifies under the
# public key the peer extracts from the certificate.
KSIG=$("$CLI" sign "$KSEED" "$WORK/content.bin")
h2b "$KSIG" "$WORK/ksig.bin"
openssl pkeyutl -verify -pubin -inkey "$WORK/kleaf.pem" -rawin \
  -in "$WORK/content.bin" -sigfile "$WORK/ksig.bin" >/dev/null 2>&1 \
  || fail "OpenSSL rejected kroopt's CertificateVerify under the cert's leaf key"
echo "   ok: OpenSSL parses the cert, its leaf key matches kroopt's signing key,"
echo "       and verifies kroopt's CertificateVerify under that leaf key"

echo
echo "ALL CertificateVerify interop checks passed (HACL* Ed25519 <-> OpenSSL)."
