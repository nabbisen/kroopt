#!/bin/sh
# tls-interop.sh — live TLS 1.3 interop: kroopt server <-> independent clients (OpenSSL + Python).
#
# Runs the verified kroopt core + production interpreter as a TLS 1.3 server on an AF_UNIX socket and
# completes a full handshake AND an application-data round-trip against OpenSSL s_client and Python's
# ssl module. Two server I/O drivers are exercised (RFC 010):
#   * kroopt-live-server    — blocking, one-record-at-a-time push driver;
#   * kroopt-live-server-nb — non-blocking, poll/readiness-driven reactor over a real socket Transport
#                             (the production I/O shape an iotakt adapter takes; Requirements §2.3/§21).
#
# An independent implementation validates kroopt's wire bytes end to end, kroopt verifies the client's
# Finished to reach `connected`, and both directions exchange application data under the TLS 1.3 traffic
# keys. kroopt's production path reaches the network only through iotakt; the socket helpers are
# test-only glue exercised here.
set -e
export PATH="$HOME/.elan/bin:$PATH"
cd "$(dirname "$0")/.."

SOCK="${TMPDIR:-/tmp}/kroopt-tls-interop.sock"
SRVOUT="${TMPDIR:-/tmp}/kroopt-tls-interop.srv"
fail=0

echo "Building kroopt live servers..."
lake build kroopt-live-server kroopt-live-server-nb 2>&1 | tail -1

start_server() {  # $1 = exe, $2 = optional extra server arg (e.g. x25519-only)
  rm -f "$SOCK"
  ( timeout 30 lake exe "$1" "$SOCK" ${2:-} > "$SRVOUT" 2>&1 ) &
  SRVPID=$!
  i=0
  while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
}

await_server() { wait "$SRVPID" 2>/dev/null || true; }

check() {  # $1 = label, $2 = condition result (0=ok)
  if [ "$2" -eq 0 ]; then echo "  $1: ok"; else echo "  $1: FAILED"; fail=$((fail+1)); fi
}

test_openssl() {  # $1 = exe, $2 = label, $3 = ciphersuite (default ChaCha20-Poly1305), $4 = groups (default x25519)
  CS="${3:-TLS_CHACHA20_POLY1305_SHA256}"
  GRP="${4:-x25519}"
  start_server "$1"
  OUT=$( (printf 'ping from openssl\n'; sleep 1) | timeout 15 openssl s_client -unix "$SOCK" -tls1_3 \
           -ciphersuites "$CS" -groups "$GRP" 2>&1 || true)
  await_server
  echo "$OUT" | grep -q "New, TLSv1.3, Cipher is $CS" \
    && grep -q "HANDSHAKE_OK reached connected" "$SRVOUT"; hs=$?
  grep -q "APP_RECV .* decrypted from client" "$SRVOUT" && grep -q "APP_SENT" "$SRVOUT"; app=$?
  check "OpenSSL [$2] TLS 1.3 handshake ($CS / $GRP)" "$hs"
  check "OpenSSL [$2] app-data received + response sealed ($CS / $GRP)" "$app"
  if [ "$hs" -ne 0 ] || [ "$app" -ne 0 ]; then echo "    --- server ---"; cat "$SRVOUT"; fi
}

test_openssl_reject() {  # $1 = exe, $2 = label, $3 = forced groups (default P-256)
  GRP="${3:-P-256}"
  start_server "$1" x25519-only
  OUT=$( (printf 'ping\n'; sleep 1) | timeout 15 openssl s_client -unix "$SOCK" -tls1_3 -groups "$GRP" 2>&1 || true)
  await_server
  # RFC 039 §8.16: an x25519-only listener must refuse a P-256-only client (no HRR) — the
  # server reaches a failed phase and never `connected`.
  grep -q "HANDSHAKE_INCOMPLETE final phase failed" "$SRVOUT" \
    && ! grep -q "HANDSHAKE_OK reached connected" "$SRVOUT"; refused=$?
  check "OpenSSL [$2] x25519-only listener refuses -groups $GRP client (RFC 039 §8.16)" "$refused"
  if [ "$refused" -ne 0 ]; then echo "    --- server ---"; cat "$SRVOUT"; fi
}

test_python() {  # $1 = exe, $2 = label
  start_server "$1"
  PYOUT=$(timeout 15 python3 - "$SOCK" << 'PY' 2>&1 || true
import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3; ctx.maximum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
try:
    ss = ctx.wrap_socket(s, server_hostname="example.com")
    print("PYTHON_OK", ss.version(), ss.cipher()[0])
    ss.sendall(b"ping from python\n")
    print("PYTHON_APP", repr(ss.recv(1024)))
    ss.close()
except Exception as e:
    print("PYTHON_FAIL", repr(e))
PY
)
  await_server
  echo "$PYOUT" | grep -q "PYTHON_OK TLSv1.3" \
    && grep -q "HANDSHAKE_OK reached connected" "$SRVOUT"; hs=$?
  echo "$PYOUT" | grep -q "kroopt: hello over TLS 1.3" \
    && grep -q "APP_RECV .* decrypted from client" "$SRVOUT"; app=$?
  check "Python [$2] TLS 1.3 handshake" "$hs"
  check "Python [$2] app-data round-trip" "$app"
  if [ "$hs" -ne 0 ] || [ "$app" -ne 0 ]; then echo "    $PYOUT" | head -2; echo "    --- server ---"; cat "$SRVOUT"; fi
}

echo
echo "=== Driver: blocking push (kroopt-live-server) ==="
test_openssl kroopt-live-server "blocking" TLS_CHACHA20_POLY1305_SHA256
test_openssl kroopt-live-server "blocking" TLS_AES_128_GCM_SHA256
test_openssl kroopt-live-server "blocking" TLS_AES_256_GCM_SHA384
test_openssl kroopt-live-server "blocking P-256" TLS_CHACHA20_POLY1305_SHA256 P-256
test_openssl_reject kroopt-live-server "blocking" P-256
test_python  kroopt-live-server "blocking"

echo
echo "=== Driver: non-blocking readiness reactor (kroopt-live-server-nb) ==="
test_openssl kroopt-live-server-nb "reactor" TLS_CHACHA20_POLY1305_SHA256
test_openssl kroopt-live-server-nb "reactor" TLS_AES_128_GCM_SHA256
test_openssl kroopt-live-server-nb "reactor" TLS_AES_256_GCM_SHA384
test_openssl kroopt-live-server-nb "reactor P-256" TLS_CHACHA20_POLY1305_SHA256 P-256
test_python  kroopt-live-server-nb "reactor"

rm -f "$SOCK"
echo
if [ "$fail" -eq 0 ]; then
  echo "ALL live TLS 1.3 interop checks passed (OpenSSL + Python; blocking + non-blocking reactor; handshake + app data)."
else
  echo "$fail live interop check(s) FAILED."
  exit 1
fi
