# End-to-end handshake (fakes)

M5 closes the v0.1 synthetic-core line: the full TLS 1.3 server handshake runs
end-to-end **through `Kroopt.Core.step`** against a fake transport and a
deterministic fake crypto provider (RFC 014). There is still no real
cryptography and no sockets — but the protocol now runs as it will in
production, just with the provider and transport faked.

## How the handshake is wired into `step`

The handshake transition functions (RFC 006) are reached through the existing
record handlers, so `step` and its *no early plaintext* proof are unchanged in
shape:

- a plaintext handshake record (outer type 22) routes to
  `handshakeOnPlaintextRecord`, which parses and validates a ClientHello in
  `start` and treats a record in `sentServerFinished` as the client Finished;
- a returning crypto result that gates a phase (the ECDHE shared secret, the
  CertificateVerify signature, the client-Finished verification) routes to
  `handshakeOnGatingResult`, which advances exactly one phase.

Both dispatches are proved to emit no application plaintext and to request no
AEAD-open, so every M2/M3 safety theorem — *no early plaintext*, *no
unauthenticated plaintext*, read/write/epoch key separation, sequence
monotonicity — continues to hold over the live handshake.

## The fake provider and transport

The fake crypto provider is deterministic and purpose-aware: ECDHE returns a
fixed handle, signing returns a fixed signature, Finished verification is
scripted to succeed or fail, and AEAD seal/open wrap a test envelope. The fake
transport logs `writeTransport` output and feeds scripted inbound bytes. The
driver loop runs `step`, executes each emitted action against the fakes, and
feeds crypto results back as events until the connection reaches `connected`.

## What the harness demonstrates

`kroopt-e2e-test` builds a real ClientHello byte sequence, frames it as a record,
and drives `step` to `connected` with a `reportHandshakeComplete` — the RFC 014
§10 acceptance. Negative traces (malformed ClientHello, application data before
`connected`, a bad client Finished) fail deterministically and, crucially, emit
no plaintext. The parser fuzz harness adds ClientHello and record-reassembly
targets to the existing primitive fuzzer.
