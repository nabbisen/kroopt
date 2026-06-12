#!/usr/bin/env bash
# RFC 032 §7 — CI gate against placeholder / first-byte handshake dispatch.
#
# The typed assembly contract (RFC 032) requires that no production module
# recognize or assemble a handshake message by a structural placeholder frame or
# by switching on a message's first byte. Every server-flight message is emitted
# as a typed `OutputAction` (writeHandshake / writeCertificate) and serialized by
# the single `serializeHandshakeOut` / `serializeServerCertificate` source.
#
# This gate fails the build if any production module under Kroopt/ contains a
# placeholder framer name or a first-byte handshake-dispatch helper. Tests are
# exempt by design (they may keep archived compatibility shims), but as of RFC
# 032 the test drivers are first-byte-free too.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Production zone: the library sources. Tests/, scripts/, docs/ are excluded.
PROD_DIR="Kroopt"

# Forbidden placeholder framers (RFC 032 §7) and the dead first-byte dispatch helper.
FORBIDDEN='frameServerHello|frameEncryptedExtensions|frameCertificate|frameCertificateVerify|frameServerFinished|appendReal'

fail=0

hits="$(grep -rnE "$FORBIDDEN" "$PROD_DIR" --include='*.lean' || true)"
if [ -n "$hits" ]; then
  echo "FAIL: placeholder framer / first-byte dispatch found in production (RFC 032 §7):"
  echo "$hits"
  fail=1
fi

# A handshake message must never be serialized by switching on its first byte in
# production. Flag obvious first-byte dispatch over handshake msg_type code points
# (2 = ServerHello, 8 = EE, 11 = Certificate, 15 = CertificateVerify, 20 = Finished)
# guarded by a `.get! 0`-style read in the same file.
for f in $(find "$PROD_DIR" -name '*.lean'); do
  if grep -qE '\.get!\s+0|\.get!\(0\)' "$f" \
     && grep -qE 'tag\s*==\s*(2|8|11|15|20)\b' "$f"; then
    echo "FAIL: possible first-byte handshake dispatch in $f (RFC 032 §7)"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "OK: no placeholder framer or first-byte handshake dispatch in production (RFC 032 §7)."
fi
exit "$fail"
