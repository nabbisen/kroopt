#!/bin/sh
# Real-ClientHello interop check (RFC 026 de-risk).
#
# Generates a genuine TLS 1.3 ClientHello with Python's `ssl` module (a real, independent TLS
# implementation built on OpenSSL) and confirms kroopt's verified core parses it, negotiates
# TLS_CHACHA20_POLY1305_SHA256 / x25519, performs the ECDHE against the client's real key_share,
# and produces a server flight. This validates the parser + policy against a real, non-fixture
# ClientHello — distinct from the deterministic RFC 8448 fixture used elsewhere. The ClientHello
# is freshly random each run (new client ephemeral + random), so this also fuzzes the happy path.
set -e
export PATH="$HOME/.elan/bin:$PATH"

CH=/tmp/real_ch.bin
python3 - "$CH" << 'PY'
import ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
obj = ctx.wrap_bio(inb, outb, server_hostname="example.com")
try:
    obj.do_handshake()
except ssl.SSLWantReadError:
    pass
ch = outb.read()
open(sys.argv[1], "wb").write(ch)
print(f"generated real TLS 1.3 ClientHello: {len(ch)} bytes (Python ssl / OpenSSL {ssl.OPENSSL_VERSION})")
PY

lake build kroopt-realch-interop >/dev/null 2>&1
OUT=$(lake exe kroopt-realch-interop)
echo "$OUT"
echo "$OUT" | grep -q "^PASS:" || { echo "FAILED: core did not parse/negotiate the real ClientHello"; exit 1; }
echo
echo "real-ClientHello interop check passed (kroopt core <-> Python ssl ClientHello)."
