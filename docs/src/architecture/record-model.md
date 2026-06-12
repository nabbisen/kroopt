# Record model

The record layer (RFC 004) is where TLS 1.3's outer/inner content-type
distinction lives, and where *no unauthenticated plaintext* is enforced
structurally.

## Outer vs inner content type

A protected TLS 1.3 record carries an **outer** content type of
`application_data` on the wire, regardless of what it actually contains; the
**real** inner content type sits inside the authenticated plaintext, after the
AEAD tag verifies. kroopt models the three shapes separately so the two can never
be confused:

- `TLSPlaintext` — an unprotected record (a real type + a size-bounded fragment),
  used for plaintext handshake records before keys exist.
- `TLSCiphertext` — a protected record: outer `application_data` plus an
  encrypted body, size-bounded to 2¹⁴ + 256.
- `TLSInnerPlaintext` — what an AEAD open yields: the real content, the real
  inner content type, and the zero padding.

Sizes are enforced by construction through `BoundedBytes max`, whose length bound
is a field — an over-length record body is unconstructable.

## The core requests crypto; it never calls it

Both directions run through the pure core as *actions*:

- **Read.** Transport bytes are reassembled; once a full record is buffered
  (`tryTakeRecord` returns `none` until then), a protected record in `connected`
  state produces a `callCrypto (aeadOpen …)` request. The returning
  `cryptoResult (aeadOpened …)` is validated (inner content type, sequence) and
  the application content is placed into the one-record `pendingPlainOut` buffer.
  An open *failure* (`verifyFailed`) is fatal — `bad_record_mac`, no plaintext.
- **Write.** A connected `send` fragments to ≤ 2¹⁴, builds the inner plaintext,
  requests `aeadSeal`, and acknowledges ownership with `acceptPlaintextBytes`.

The interpreter (a later milestone) will execute those actions against real
crypto; the core makes every protocol decision.

## What is proved

- **No unauthenticated plaintext.** `buffered_plaintext_authenticated`: plaintext
  is buffered only by a successful `aeadOpened` result in `connected` state.
  Combined with the single connected-gated emit site, plaintext reaches the
  application only via an authenticated, connected open.
- **Auth failure is silent and fatal.** `aead_open_failure_no_plaintext`.
- **Handlers never leak plaintext.** The read/result/send handlers provably emit
  no `emitPlaintext` and accept none outside the connected send path.

The crypto provider's guarantee that `aeadOpened` means *verified* is ASSUMED
(HACL\*/EverCrypt); kroopt proves the structural half — that nothing reaches the
application except through that authenticated path.

## CCS compatibility and sequence numbers

A single `change_cipher_spec` record with body `0x01` is accepted-and-ignored
(`classifyCcs`); every other CCS is rejected. The accept-and-ignore decision is
made in the core, never hidden in the interpreter. Sequence numbers are
per-direction and overflow-checked before use (`SeqNo.next` returns `none` at the
`UInt64` ceiling, forcing failure before nonce derivation); the nonce-uniqueness
and monotonicity *proofs* themselves land at M3 (RFC 005).
