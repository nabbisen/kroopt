# Theorem inventory

This is the live register of machine-checked theorems in the kroopt verified
core (RFC 022 §6). Every entry names the module, the property in plain language,
the governing RFC, and its status. The CI proof gate (`scripts/check-hygiene.sh`)
guarantees none of these depends on `sorry`, `axiom`, or `unsafe`.

To regenerate the axiom-dependency facts below:

```
lake env lean -e 'import Kroopt.Proofs
open Kroopt.Core.Proofs
#print axioms no_plaintext_emit_unless_connected'
```

## Status legend

* **proved** — fully machine-checked in the current tree, no `sorry`.
* **planned** — stated in an RFC, scheduled for the named milestone, not yet in
  the tree (and therefore *not* present as a `sorry` — absent rather than
  assumed).

## M0 — proved

| # | Theorem | Module | Property | RFC | Axioms | Status |
|---|---------|--------|----------|-----|--------|--------|
| 1 | `step_deterministic` | `Kroopt.Proofs.Basic` | `step` is a pure total function: one result per (state, event). | RFC 002 §7 | none | proved |
| 2 | `terminal_absorbing` | `Kroopt.Proofs.Basic` | In a terminal phase, every event leaves state unchanged and emits no actions. | RFC 013 §7 | propext | proved |
| 3 | `terminal_no_error` | `Kroopt.Proofs.Basic` | A terminal step never errors; it always absorbs. | RFC 013 §7 | propext | proved |
| 4 | `no_plaintext_emit_unless_connected` | `Kroopt.Proofs.ActionDiscipline` | `emitPlaintext` is emitted only when the phase is `connected` — *no early plaintext*. | RFC 002 §7, RFC 015 §15.1 | propext | proved |
| 5 | `no_plaintext_after_terminal` | `Kroopt.Proofs.ActionDiscipline` | A terminal connection emits no plaintext at all. | RFC 013 §7 | propext | proved |

All five are confirmed to depend only on `propext` (theorem 1 on no axioms at
all), never on `sorryAx`.

## M1 — proved (parser foundation)

The bounds-safety theorems for the parser foundation (RFC 003 §9.3). Each says a
successful read advances the cursor monotonically and leaves it within the
buffer, without changing the buffer — the in-bounds part is structural (the
`Reader.inBounds` field), and the proofs add monotonicity and
input-preservation. They live in `Kroopt.Parse.Proofs` (module
`Kroopt.Proofs.ParserBounds`).

| # | Theorem | Property | RFC | Axioms | Status |
|---|---------|----------|-----|--------|--------|
| 6 | `reader_in_bounds` | A reader's cursor never points past its buffer (the field is the proof). | RFC 003 §9.1 | none | proved |
| 7 | `takeBytes_bounds` | The one primitive read advances by exactly `n`, stays in bounds, preserves the buffer. | RFC 003 §9.1, §9.3 | propext | proved |
| 8 | `takeBytes_mono` | Monotonicity + input-preservation form of the above. | RFC 003 §9.3 | propext | proved |
| 9 | `takeU8_bounds`, `takeU16_bounds`, `takeU24_bounds`, `takeU32_bounds` | Each fixed-width integer read is bounds-safe (via `takeBytes`). | RFC 003 §9.1 | propext | proved |
| 10 | `takeLen_bounds` | Length-prefix reads (8/16/24-bit) are bounds-safe. | RFC 003 §9.1 | propext, Quot.sound | proved |
| 11 | `takeVectorBytes_bounds` | A budgeted, length-prefixed byte vector is bounds-safe — the framer the record/extension parsers build on. | RFC 003 §6, §9.3 | propext, Quot.sound | proved |
| 12 | `parser_bounds_safe` | Umbrella: a successful foundational read advances monotonically and stays within the buffer. | RFC 003 §9.3, §15 | propext | proved |

All confirmed via `#print axioms` to depend only on `propext` (some also on
`Quot.sound`, introduced by `simp`/`contradiction`), never on `sorryAx`.

## M2 — proved (TLS 1.3 record model)

The record-layer safety theorems (RFC 004 §10, RFC 015 §15.1). The headline is
*no unauthenticated plaintext*: application plaintext is buffered only by a
successful, authenticated AEAD open in `connected` state, and the sole emitter
reads that buffer — so nothing reaches the application that did not come from an
authenticated, connected-state record open. They live in `Kroopt.Core.Proofs`
(module `Kroopt.Proofs.RecordPath`), and the M0 *no early plaintext* theorem was
re-proved over the extended `step`.

| # | Theorem | Property | RFC | Axioms | Status |
|---|---------|----------|-----|--------|--------|
| 13 | `buffered_plaintext_authenticated` | Newly-buffered application plaintext implies a successful `aeadOpened` result in `connected` state — the no-unauthenticated-plaintext headline. | RFC 004 §10, RFC 015 §15.1 | propext | proved |
| 14 | `buffered_plaintext_provenance` | Step-level form: a step that newly buffers plaintext was processing an `aeadOpened` result while `connected`. | RFC 004 §10 | propext, Quot.sound | proved |
| 15 | `aead_open_failure_no_plaintext` | An AEAD-open verification failure emits no plaintext, clears the buffer, and is terminal (`bad_record_mac`). | RFC 004 §12 | propext, Quot.sound | proved |
| 16 | `handleTransportBytes_no_plaintext` / `handleCryptoResult_no_plaintext` / `handleAppSend_no_plaintext` | No record handler ever emits `emitPlaintext` (emission stays at the single connected-gated site). | RFC 004 §5.7 | propext (one also Quot.sound) | proved |
| 17 | `handleTransportBytes_no_accept` / `handleCryptoResult_no_accept` | No inbound handler accepts application plaintext (only the connected send path does). | RFC 004 §9 | propext (one also Quot.sound) | proved |
| 18 | `no_plaintext_emit_unless_connected` (re-proved) | Still holds over the extended `step`: plaintext is emitted only in `connected`. | RFC 002 §7 | propext, Quot.sound | proved |
| 19 | `accept_plaintext_only_connected` | Application plaintext is accepted (ownership taken) only in `connected`. | RFC 002 §7, RFC 004 §9 | propext, Quot.sound | proved |

All confirmed via `#print axioms` to depend only on `propext` (some also
`Quot.sound`), never `sorryAx`.

Note on the trust boundary: `aeadOpened` standing for an *authenticated* open is
the crypto provider's contract (ASSUMED — HACL\*/EverCrypt), not something kroopt
proves. What kroopt proves is that buffered/emitted plaintext is reachable
*only* through that authenticated path — the structural half of the guarantee.

## M3 — proved (nonce, sequence, epoch, key separation)

The record layer's cryptographic discipline (RFC 005 §7). Nonce reuse breaks AEAD
catastrophically, so these are proof targets rather than tested conventions. They
live in `Kroopt.Core.Proofs` (modules `Kroopt.Proofs.Nonces` and
`Kroopt.Proofs.KeySeparation`), with the `SeqNo` increment/overflow facts in the
core.

| # | Theorem | Property | RFC | Axioms | Status |
|---|---------|----------|-----|--------|--------|
| 20 | `SeqNo.next_some_succ` / `SeqNo.next_none_overflow` | A successful increment is exactly `+1`; `next` returns `none` only at the `UInt64` ceiling. | RFC 005 §7.1–7.2 | propext | proved |
| 21 | `successful_seal_increments_write_seq` | A successful seal advances the write sequence by exactly one. | RFC 005 §7.1 | propext | proved |
| 22 | `successful_open_increments_read_seq` | A successful open (that buffers content) advances the read sequence by exactly one. | RFC 005 §7.1 | propext | proved |
| 23 | `no_crypto_on_write_seq_overflow` | At the sequence ceiling a send requests no crypto and fails — no seal with a wrapped sequence (no silent wrap). | RFC 005 §7.2 | propext | proved |
| 24 | `nonce_unique_within_epoch` | For a fixed IV base, distinct sequence values derive distinct nonces. | RFC 005 §7.3 | none | proved |
| 25 | `aeadSeal_uses_write_keys` | Every seal request carries write-direction, application-epoch metadata. | RFC 005 §7.4–7.5 | propext | proved |
| 26 | `aeadOpen_uses_read_keys` | Every open request carries read-direction, application-epoch metadata. | RFC 005 §7.4–7.5 | propext, Quot.sound | proved |

All confirmed via `#print axioms` to depend only on `propext` (`nonce_unique_within_epoch` on no axioms at all; one also on `Quot.sound`), never `sorryAx`.

Note on the nonce model: the uniqueness proof is over `deriveNonce`, which models
the per-record nonce as the public IV-base identity plus the sequence value — the
data the security argument needs. The concrete `iv_base XOR left_pad(seq)`
realization (`nonceBytes`) is provided for the interpreter and known-answer tests
(M6); for a fixed IV base it is a bijection in the sequence, so it preserves the
proved uniqueness. RFC 005 §5 explicitly sanctions representing the IV base
abstractly.

## M4 — proved (handshake state model + transcript binding)

The handshake state machine without HelloRetryRequest (RFC 006) and the
exact-wire-byte transcript (RFC 007). The handshake is a sequence of small
transition functions; the transcript is an ordered log of the exact committed
bytes. Proofs live in `Kroopt.Proofs.Handshake`, `Kroopt.Proofs.Transcript`, and
(for the deferred composition lemma) `Kroopt.Parse.Proofs`.

| # | Theorem | Property | RFC | Axioms | Status |
|---|---------|----------|-----|--------|--------|
| 27 | `onClientHello_legal` … `onClientFinishedVerified_legal` (×5) | Every handshake transition moves the phase along a `legalEdge` — no skipped or out-of-order phases. | RFC 006 §4, §9 | propext | proved |
| 28 | `connected_requires_finished_verified` | `connected` is reachable only from `requestedClientFinishedVerify`, and only when the client Finished verified — so no application data flows before it is checked. | RFC 006 §9 | propext | proved |
| 29 | `appendFramed_binds_exact_bytes` / `appendParsed_uses_wire_bytes` | The transcript commits the exact framed/consumed bytes verbatim — never a reconstruction. | RFC 007 §6 | propext | proved |
| 30 | `appendFramed_preserves_order` / `appendFramed_increments_count` | Appends extend the event sequence in order, one message at a time. | RFC 007 §8 | none / propext | proved |
| 31 | `snapshot_eventCount` / `snapshot_then_append_is_before` | A snapshot covers exactly the committed prefix, so a Finished/CertificateVerify input built before appending message M covers up to but not including M. | RFC 007 §8 | propext | proved |
| 32 | `takeCountedItems_bounds` | The fuel-bounded item combinator is bounds-safe given a bounds-safe item parser (composition lemma deferred from M1). | RFC 003 §9.3 | propext | proved |

All confirmed via `#print axioms` to depend only on `propext` (two on no axioms
at all), never `sorryAx`.

Notes on the model: the handshake key-schedule HKDF derivations are modeled as
synchronous key installation (the gating crypto round-trips — ECDHE, the
CertificateVerify signature, the client-Finished verification — are real actions
whose results re-enter as events); the provider-backed HKDF round-trips arrive at
M6. The transcript stores the exact bytes for the binding proof; the running hash
is a provider action (RFC 007 §9.1 permits this hybrid). The synthetic handshake
drives the transition functions directly to `connected`; wiring them into the
live `step` event loop against the fake transport/provider is M5.

## M5 — proved (live handshake preserves no early plaintext)

M5 wires the handshake transition functions into the live `step` dispatcher (via
the record handlers) and drives the full synthetic handshake end-to-end through
`step` against a fake transport and fake crypto provider (RFC 014). The headline
guarantee is that the M2/M3 safety theorems — above all *no early plaintext* —
**still hold over the live handshake**: that is the proof/runtime correspondence
contract (RFC 002 §5). New supporting lemmas, in `Kroopt.Proofs.Handshake` and
`Kroopt.Proofs.RecordPath`:

| # | Theorem | Property | RFC | Axioms | Status |
|---|---------|----------|-----|--------|--------|
| 33 | `handshakeOnPlaintextRecord_no_emit` / `_no_accept` | The plaintext-handshake-record dispatch (ClientHello / client Finished) emits and accepts no application plaintext. | RFC 002 §7 | propext, Quot.sound | proved |
| 34 | `handshakeOnGatingResult_no_emit` / `_no_accept` | The gating-result dispatch (ECDHE / signature / verify) emits and accepts no application plaintext. | RFC 002 §7 | propext | proved |
| 35 | `handshakeOnPlaintextRecord_no_aeadOpen` | The handshake dispatch requests no AEAD-open, so `aeadOpen_uses_read_keys` still characterises every record open. | RFC 005 §6 | propext, Quot.sound | proved |
| 36 | `onClientHello_no_emit` … `onClientFinishedVerified` (transition no-emit/no-accept/no-aeadOpen family) | Each handshake transition emits only `callCrypto`/`writeTransport`/`reportHandshakeComplete`/alerts. | RFC 006 §10 | propext | proved |

The pre-existing headline theorems were re-checked unchanged over the new live
handshake: `no_plaintext_emit_unless_connected`, `accept_plaintext_only_connected`,
`buffered_plaintext_authenticated`, `aead_open_failure_no_plaintext`,
`aeadOpen_uses_read_keys`, and `successful_open_increments_read_seq` all still
build and depend only on `propext` (+ `Quot.sound`). The end-to-end harness
(`kroopt-e2e-test`) drives a real ClientHello byte sequence through `step` to
`connected`, and the negative traces (malformed ClientHello, early application
data, bad client Finished) fail deterministically and emit no plaintext.

## M6 — proved (crypto-result correlation)

M6 adds the crypto provider boundary (RFC 008 / 009). The verification-first
contribution is the **operation-id correlation guard**: `handleCryptoResult`
processes a result only if its operation id is currently outstanding. The native
HACL\*/EverCrypt shim is contracted (`Kroopt/Native/kroopt.h`) with its build
deferred until HACL\* is vendored; the deterministic `Kroopt.Crypto.fakeProvider`
stands in, and the correlation guarantee holds regardless of provider.

| # | Theorem | Property | RFC | Axioms | Status |
|---|---------|----------|-----|--------|--------|
| 37 | `stale_crypto_result_rejected` | A crypto result whose operation id is not outstanding (stale / duplicate / forged) is a complete no-op — state unchanged, no actions. | RFC 008 §5 | propext | proved |
| 38 | `stale_crypto_result_no_plaintext` | A stale crypto result emits no application plaintext (corollary). | RFC 008 §5 | propext | proved |

All M2–M5 safety theorems were re-checked over the guarded `handleCryptoResult`
and still hold; `aead_open_failure_no_plaintext` now carries an explicit
"operation outstanding" hypothesis (a stale failure is dropped instead, by the
theorem above). Capability negotiation (`validateCapabilities`) is a total
deterministic function exercised by `kroopt-crypto-test`, not a proof target.

## M7 — interpreter faithfulness (TESTED, not new theorems)

M7 adds the runtime layer (RFC 010): the `TlsConn` API and the thin interpreter.
It introduces **no new core theorems** — by design. The interpreter's correctness
is the *faithfulness* of action execution, which the trust matrix classes as
TESTED, not PROVEN (`kroopt-conn-test`: full handshake through `TlsConn`, write
ownership / `wouldBlock`-consumes-zero, flush drains, partial-write ordering,
progress-budget termination, stale-event rejection). What keeps the *proved*
guarantees in force over the running connection is structural: `execAction` does
not take the core `State`, so the interpreter cannot make a protocol decision —
all protocol truth remains in `step`, which every M0–M6 theorem constrains.

## Planned — later milestones
