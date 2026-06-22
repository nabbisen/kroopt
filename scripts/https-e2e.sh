#!/bin/sh
# https-e2e.sh — end-to-end HTTPS: a real HTTP client speaks HTTPS to kroopt.
#
# The v0.3 vision (RFC 015): a Lean edge server terminates TLS 1.3 itself and answers an HTTP request.
# kroopt provides the verified TLS channel; `Tests/LiveServerNb.lean` in `http` mode runs a minimal
# fixed HTTP/1.1 handler over it (standing in for jemmet, which owns HTTP semantics in production) and
# closes gracefully with a sealed `close_notify`. Two independent HTTP clients validate the whole stack
# — TLS handshake, the presented certificate, the encrypted application records carrying real HTTP, and
# a clean TLS shutdown:
#   * curl 8.5 (OpenSSL) over the unix socket;
#   * Python `ssl` + a raw HTTP GET, which also asserts the close is graceful (clean EOF, not a
#     truncation error).
set -e
export PATH="$HOME/.elan/bin:$PATH"
cd "$(dirname "$0")/.."

SOCK="${TMPDIR:-/tmp}/kroopt-https-e2e.sock"
SRVOUT="${TMPDIR:-/tmp}/kroopt-https-e2e.srv"
fail=0

echo "Building kroopt HTTPS server..."
lake build kroopt-live-server-nb 2>&1 | tail -1

start_server() {
  rm -f "$SOCK"
  ( timeout 30 lake exe kroopt-live-server-nb "$SOCK" http > "$SRVOUT" 2>&1 ) &
  SRVPID=$!
  i=0; while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
}
await_server() { wait "$SRVPID" 2>/dev/null || true; }
check() { if [ "$2" -eq 0 ]; then echo "  $1: ok"; else echo "  $1: FAILED"; fail=$((fail+1)); fi; }

server_served() {
  grep -q "HTTP_REQ .* received over TLS" "$SRVOUT" \
    && grep -q "HTTP_RESP 200 sent over TLS" "$SRVOUT" \
    && grep -q "CLOSE_NOTIFY sent (graceful)" "$SRVOUT"
}

echo
echo "=== Client 1: curl (OpenSSL) over HTTPS ==="
start_server
OUT=$(curl -sk --tlsv1.3 --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256 --curves X25519 \
        --unix-socket "$SOCK" https://example.com/ 2>/tmp/kroopt-curl.err); rc=$?
await_server
echo "$OUT" | grep -q "kroopt" && [ "$rc" -eq 0 ]; body=$?
server_served; srv=$?
check "curl received the HTML body (clean exit)" "$body"
check "server terminated TLS + served HTTP + graceful close" "$srv"
if [ "$body" -ne 0 ] || [ "$srv" -ne 0 ]; then
  echo "    curl rc=$rc"; head -2 /tmp/kroopt-curl.err; echo "    --- server ---"; cat "$SRVOUT"
fi

echo
echo "=== Client 2: Python ssl + raw HTTP GET (asserts graceful close) ==="
start_server
PYOUT=$(timeout 15 python3 - "$SOCK" << 'PY' 2>&1 || true
import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3; ctx.maximum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
try:
    ss = ctx.wrap_socket(s, server_hostname="example.com")
    ss.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    resp = b""; clean = False
    while True:
        try:
            chunk = ss.recv(4096)
        except ssl.SSLError as e:
            print("PY_TRUNCATED", repr(e)); break
        if not chunk:
            clean = True; break          # clean close_notify -> empty read, no error
        resp += chunk
    status = resp.split(b"\r\n", 1)[0].decode("latin1")
    print("PY_STATUS", status)
    print("PY_BODY_HAS_KROOPT", b"kroopt" in resp)
    print("PY_CLEAN_CLOSE", clean)
except Exception as e:
    print("PY_FAIL", repr(e))
PY
)
echo "$PYOUT" | grep -E 'PY_STATUS|PY_BODY_HAS_KROOPT|PY_CLEAN_CLOSE|PY_TRUNCATED|PY_FAIL'
await_server
echo "$PYOUT" | grep -q "PY_STATUS HTTP/1.1 200 OK" \
  && echo "$PYOUT" | grep -q "PY_BODY_HAS_KROOPT True"; http=$?
echo "$PYOUT" | grep -q "PY_CLEAN_CLOSE True"; clean=$?
check "Python received HTTP/1.1 200 OK with body" "$http"
check "Python observed a graceful TLS close (no truncation)" "$clean"
if [ "$http" -ne 0 ] || [ "$clean" -ne 0 ]; then echo "    --- server ---"; cat "$SRVOUT"; fi

rm -f "$SOCK"
echo
if [ "$fail" -eq 0 ]; then
  echo "ALL HTTPS end-to-end checks passed (curl + Python; TLS 1.3 termination + HTTP/1.1 + graceful close)."
else
  echo "$fail HTTPS e2e check(s) FAILED."
  exit 1
fi
