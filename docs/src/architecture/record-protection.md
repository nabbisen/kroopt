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

## Opening the protected client Finished in-core (RFC 033, part 1)

The client Finished arrives as a protected record (outer `application_data`) sealed
under the client handshake-traffic key. The core opens it **before `connected`**:
`handleTransportBytes` emits an `aeadOpen` under the **handshake** read epoch
(`readMeta` follows `readEpoch.epoch`), and the opened inner handshake message is
routed through the handshake model (`handshakeOnPlaintextRecord` →
`onClientFinishedBytes`) to a `verifyFinished` request, then `connected`. Inner
application data before `connected` is a fatal protocol violation, and the open
never fills the application-plaintext buffer — the no-early / no-unauthenticated
plaintext proofs are preserved (`buffered_plaintext_authenticated`).

The read epoch stays `handshake` through `sentServerFinished` (the server's *write*
switches to application after its own Finished) and becomes `application` only once
the client Finished verifies. `KeySeparation.aeadOpen_uses_read_keys` proves an open
always uses read-direction keys at the connection's current read epoch.

## The change_cipher_spec phase window (RFC 8446 §5)

TLS 1.3 keeps a vestigial `change_cipher_spec` record only for middlebox
compatibility: a client may send a single one-byte CCS, which the server ignores.
RFC 8446 §5 confines it to the handshake — it is permitted only after the ClientHello
is received and before the client's Finished, and an implementation that receives one
at any other time MUST abort.

The record path enforces both halves. `classifyCcs` validates the payload (exactly one
byte, 0x01; anything else is rejected), and `handleTransportBytes` gates acceptance on
the handshake phase: a compatibility CCS is accepted-and-ignored only in an active
handshake phase. A CCS arriving before any ClientHello (`start`), after `connected`, or
while closing or terminal is rejected as an illegal record (`unexpectedMessage`). The
classification is returned to the core and the gate lives in the core — neither is
hidden in the interpreter.

## Handshake-message reassembly (RFC 033)

The record layer frames TLS *records*; a handshake *message* is a separate framing
inside the record stream (a 1-byte msg_type, a 3-byte length, then the body) and a single
message may span several records or, in principle, several may share one. The record path
keeps a small reassembly buffer (`State.handshakeReasm`) for this second layer: each
plaintext handshake record's body is appended to the buffer, then `frameHandshakeMessage`
peels off one complete message — header included, as the handshake model expects — and
leaves any tail for the next record. While a message is still incomplete the buffer is
retained and the interpreter is asked to read more; if the buffer ever exceeds
`maxHandshakeReasmBytes` the connection fails rather than buffering without bound.

The buffer is a plain `ByteArray` with that runtime cap, mirroring `inboundCiphertext`;
no proof reasons about its size. The only proof obligation the new branch carries is the
same one the rest of the record path carries — that it emits no application plaintext —
and the existing `pendingPlainOut`-preservation lemmas discharge it unchanged. The
practical effect is that a ClientHello fragmented across records now parses correctly; it
previously reached the parser as a truncated message and was rejected.
