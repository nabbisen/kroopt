#!/usr/bin/env bash
# record-interop.sh — cross-implementation check of kroopt's TLS 1.3 record layer.
#
# kroopt (Kroopt.Conn.Record13, ChaCha20-Poly1305) seals real TLSCiphertext records;
# an independent implementation (Python's `cryptography`) derives the traffic key/IV
# from the secret per RFC 8446 §7.3, reconstructs the §5.3 nonce and §5.2 AAD, and
# opens them. If an outside implementation can decrypt kroopt's records and recover
# the exact plaintext + inner content type, the record layer is standards-compliant,
# not merely self-consistent. Also checks that a tampered record is rejected.
#
# Requires: the kroopt-wire-dump exe (built by lake), python3 + cryptography.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.elan/bin:$PATH"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/open.py" << 'PY'
import sys
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2,"big") + bytes([len(full)]) + full + bytes([0])  # empty context
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)

def nonce(iv, seq):
    s = seq.to_bytes(8,"big"); n = bytearray(iv)
    for i in range(8): n[4+i] ^= s[i]
    return bytes(n)

CT = {20:"changeCipherSpec",21:"alert",22:"handshake",23:"applicationData"}
secret = None; recs = []
for line in sys.stdin:
    t = line.split()
    if not t: continue
    if t[0] == "SECRET": secret = bytes.fromhex(t[1])
    elif t[0] == "REC": recs.append((t[1], int(t[2]), bytes.fromhex(t[3]), bytes.fromhex(t[4])))

assert secret is not None, "no secret emitted"
key = hkdf_expand_label(secret, b"key", 32)
iv  = hkdf_expand_label(secret, b"iv", 12)
aead = ChaCha20Poly1305(key)
ok = 0
for name, seq, plain, sealed in recs:
    aad, body = sealed[:5], sealed[5:]
    assert sealed[0] == 0x17 and sealed[1:3] == b"\x03\x03", f"{name}: not a TLSCiphertext"
    assert int.from_bytes(sealed[3:5],"big") == len(body), f"{name}: bad length field"
    inner = aead.decrypt(nonce(iv, seq), body, aad)          # raises on auth failure
    i = len(inner)
    while i > 0 and inner[i-1] == 0: i -= 1
    content, ctype = inner[:i-1], inner[i-1]
    assert content == plain, f"{name}: plaintext mismatch"
    assert CT.get(ctype) == name, f"{name}: content type mismatch (got {ctype})"
    print(f"   ok: independently decrypted {name} record (seq {seq}), {len(content)} octets, type matches")
    ok += 1

name, seq, plain, sealed = recs[0]
bad = bytearray(sealed); bad[-1] ^= 0xFF
try:
    aead.decrypt(nonce(iv, seq), bytes(bad)[5:], bytes(bad)[:5])
    print("INTEROP FAIL: tampered record decrypted"); sys.exit(1)
except Exception:
    print("   ok: tampered record rejected by the independent implementation")

assert ok == len(recs)
print(f"\nALL record-layer interop checks passed (kroopt Record13 <-> Python cryptography), {ok} records.")
PY

echo "== kroopt seals real TLS 1.3 records =="
lake exe kroopt-wire-dump > "$WORK/dump.txt"
sed 's/\(.\{72\}\).*/\1.../' "$WORK/dump.txt"
echo "== an independent implementation (Python cryptography) opens them =="
python3 "$WORK/open.py" < "$WORK/dump.txt"
