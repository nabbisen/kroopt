#!/bin/sh
# tls-interop.sh — live TLS 1.3 handshake interop: kroopt server <-> independent clients.
#
# Starts the verified kroopt core + production interpreter as a TLS 1.3 server on an AF_UNIX
# socket (Tests/LiveServer.lean, real OS entropy, fixture Ed25519 cert) and drives a full
# handshake against OpenSSL s_client and Python's ssl module. This is the v0.3 interop target
# (RFC 026): an *independent* implementation validates kroopt's wire bytes end to end — the
# ServerHello, the encrypted flight, the presented certificate, the CertificateVerify signature,
# and the server Finished — and kroopt verifies the client's Finished to reach `connected`.
#
# kroopt's production path reaches the network only through iotakt; the socket helpers are
# test-only glue exercised here.
set -e
export PATH="$HOME/.elan/bin:$PATH"
cd "$(dirname "$0")/.."

SOCK="${TMPDIR:-/tmp}/kroopt-tls-interop.sock"
SRVOUT="${TMPDIR:-/tmp}/kroopt-tls-interop.srv"
fail=0

echo "Building kroopt live server..."
lake build kroopt-live-server 2>&1 | tail -1

start_server() {
  rm -f "$SOCK"
  ( timeout 30 lake exe kroopt-live-server "$SOCK" > "$SRVOUT" 2>&1 ) &
  SRVPID=$!
  i=0
  while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
}

server_reached_connected() {
  wait "$SRVPID" 2>/dev/null || true
  grep -q "HANDSHAKE_OK reached connected" "$SRVOUT"
}

echo
echo "=== Client 1: OpenSSL s_client ==="
start_server
OUT=$(printf 'ping from openssl\n' | timeout 15 openssl s_client -unix "$SOCK" -tls1_3 \
        -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups x25519 \
        2>&1 || true)
if echo "$OUT" | grep -q "New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256" \
   && server_reached_connected; then
  echo "  OpenSSL completed a TLS 1.3 handshake (ChaCha20-Poly1305): ok"
else
  echo "  OpenSSL handshake FAILED"
  echo "$OUT" | grep -iE 'error|alert' | head -3
  echo "  --- server output ---"; cat "$SRVOUT"
  fail=$((fail+1))
fi
if echo "$OUT" | grep -q "kroopt: hello over TLS 1.3" \
   && grep -q "APP_RECV .* decrypted from client" "$SRVOUT" \
   && grep -q "APP_SENT" "$SRVOUT"; then
  echo "  OpenSSL app-data round-trip (client record decrypted, server response read): ok"
else
  echo "  OpenSSL app-data round-trip FAILED"
  echo "  --- server output ---"; cat "$SRVOUT"
  fail=$((fail+1))
fi

echo
echo "=== Client 2: Python ssl ==="
start_server
PYOUT=$(timeout 15 python3 - "$SOCK" << 'PY' 2>&1 || true
import socket, ssl, sys
sock_path = sys.argv[1]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket(socket.AF_UNIX)
s.connect(sock_path)
try:
    ss = ctx.wrap_socket(s, server_hostname="example.com")
    print("PYTHON_OK", ss.version(), ss.cipher()[0])
    ss.sendall(b"ping from python\n")
    data = ss.recv(1024)
    sys.stdout.write("PYTHON_APP " + repr(data) + "\n")
    ss.close()
except Exception as e:
    print("PYTHON_FAIL", repr(e))
PY
)
echo "  $(echo "$PYOUT" | grep -E 'PYTHON_OK|PYTHON_APP|PYTHON_FAIL' | head -2 | tr '\n' ' ')"
if echo "$PYOUT" | grep -q "PYTHON_OK TLSv1.3" && server_reached_connected; then
  echo "  Python ssl completed a TLS 1.3 handshake: ok"
else
  echo "  Python ssl handshake FAILED"
  echo "  --- server output ---"; cat "$SRVOUT"
  fail=$((fail+1))
fi
if echo "$PYOUT" | grep -q "kroopt: hello over TLS 1.3" \
   && grep -q "APP_RECV .* decrypted from client" "$SRVOUT" \
   && grep -q "APP_SENT" "$SRVOUT"; then
  echo "  Python app-data round-trip (client record decrypted, server response read): ok"
else
  echo "  Python app-data round-trip FAILED"
  echo "  --- server output ---"; cat "$SRVOUT"
  fail=$((fail+1))
fi

rm -f "$SOCK"
echo
if [ "$fail" -eq 0 ]; then
  echo "ALL live TLS 1.3 interop checks passed (kroopt server <-> OpenSSL + Python)."
else
  echo "$fail live interop check(s) FAILED."
  exit 1
fi
