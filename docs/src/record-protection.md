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

## Scope

This is the record-protection framing and a demonstration over the live handshake's
keys. The verified core does not yet emit the seal/open actions for the handshake
flight itself (the flight is still assembled in the clear in the driver), and the
records are not yet driven over a socket. Wiring record protection into the core's
send/receive path and the iotakt socket transport (RFC 010) is next, after which
OpenSSL/curl interop (RFC 015 / 026) becomes testable. The verified core and its 87
theorems are untouched by this milestone; `Record13` is an impure-zone module plus
its test.
