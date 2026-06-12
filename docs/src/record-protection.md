# Real TLS 1.3 record protection

`Kroopt/Conn/Record13.lean` is the record-protection framing the AEAD primitives sit
under. It turns a plaintext message plus its content type into a real `TLSCiphertext`
record on the wire, and back, using ChaCha20-Poly1305 (RFC 8446 §5.2):

- **Inner plaintext** (`innerPlaintext`): `content || content_type || zero*`.
- **Additional data** (`recordAAD`): the TLSCiphertext header —
  `opaque_type(0x17) || legacy_record_version(0x0303) || ciphertext_length`.
- **Per-record nonce** (`Kroopt.Crypto.Real.nonce`): the static IV XOR the
  big-endian sequence number (RFC 8446 §5.3).
- **Seal / open** (`sealRecord` / `openRecord`): ChaCha20-Poly1305 under that AAD and
  nonce, wrapping/unwrapping the outer record. On open, the zero padding is stripped
  to recover the content and inner content type. No plaintext escapes a framing or
  authentication failure.

The vendored HACL subset provides ChaCha20-Poly1305 (no AES-GCM), so this is the
record cipher and these are self-consistent round-trips rather than a replay of RFC
8448 §3 (which uses AES-128-GCM).

`Tests.Record13` (`kroopt-record13-test`, 11 checks) covers the round-trip, the wire
structure (outer `application_data`, `0x0303`, length, tag-expanded size), that the
body is ciphertext, padding stripping, content-type recovery for `handshake` and
`application_data`, and the authentication failures that must yield no plaintext —
a tampered record, the wrong key, and the wrong sequence number (the nonce binds the
sequence).

## End to end with the live handshake

`Tests.RealHandshake` now closes the loop: after the live `step`-driven handshake
reaches `connected`, it derives the server application-traffic key/IV from the
secret the handshake produced and protects a real application-data record with
`Record13`, confirming it round-trips and that the record body is genuine
ciphertext. The negotiated keys from the live handshake protect real records.

## Cross-implementation interop

`scripts/record-interop.sh` checks the record layer against an outside
implementation: `kroopt-wire-dump` emits real sealed records, and Python's
`cryptography` library independently derives the traffic key/IV from the secret
(RFC 8446 §7.3 HKDF-Expand-Label), reconstructs the §5.3 nonce and §5.2 AAD, and
opens them — recovering the exact plaintext and inner content type, and rejecting a
tampered record. Because a non-kroopt implementation decrypts kroopt's records, the
record layer is standards-compliant, not merely self-consistent.

## The flight is encrypted on the wire

`Tests.RealHandshake` now applies record protection across the whole live handshake,
in the interpreter layer where the production driver will host it. The ServerHello
goes in the clear; the rest of the server flight (EncryptedExtensions, Certificate,
CertificateVerify, Finished) is sealed as four real `TLSCiphertext` records under the
server handshake-traffic key with handshake-epoch sequence numbers 0–3, and each is
checked to decrypt back to its plaintext handshake message. Inbound, the client's
Finished arrives as a real encrypted record; the interpreter opens it with the client
handshake-traffic key and feeds the recovered plaintext to the core, which works on
plaintext handshake messages plus crypto operations (its design). The transcript hash
is still taken over the plaintext messages (RFC 8446 §4.4.1), not the records.

## Scope

The wire is now genuine TLS 1.3 records, but the seal/open still lives in the test
driver rather than the production `Conn.Interpreter`, and the records are exchanged
in memory rather than over a socket. Folding this into the production send/receive
path and the iotakt socket transport (RFC 010) is next, after which OpenSSL/curl
interop (RFC 015 / 026) becomes testable. The verified core and its 87 theorems are
untouched; `Record13` and the driver wiring are impure-zone code.
