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

## Planned — later milestones

These are required by the RFCs and tracked here so the inventory shows the whole
target, not only what is done. They are absent from the tree (not stubbed with
`sorry`) until their milestone.

| Theorem (working name) | Property | RFC | Milestone |
|------------------------|----------|-----|-----------|
| `seq_monotonic` | Record sequence numbers strictly increase within an epoch; no reuse. | RFC 005 §7.1 | M3 |
| `seq_overflow_fatal` | A sequence at `UInt64` max forces failure before nonce derivation. | RFC 005 §7.2 | M3 |
| `nonce_unique_per_key` | No two seals under one key/epoch use the same nonce. | RFC 005 §7.3 | M3 |
| `key_separation` | Read/write and handshake/application key material never alias. | RFC 005 §7.5 | M3 |
| `no_unauth_plaintext` | Plaintext is emitted only after a successful AEAD open + inner content-type check. | RFC 004 §9, RFC 002 §7 | M2 |
| `handshake_transitions_legal` | Every reachable `HandshakeState` transition is an allowed edge. | RFC 006 §4 | M4 |
| `transcript_exact_bytes` | The transcript binds exactly the wire bytes, in order. | RFC 007 §5 | M4 |
| `takeCountedItems_bounds` | The fuel-bounded item combinator is bounds-safe given a bounds-safe item parser (composition lemma). | RFC 003 §9.3 | M4 |
| `accept_plaintext_only_connected` | `acceptPlaintextBytes` occurs only when `connected`. | RFC 002 §7 | M2 |
| `crypto_result_correlation` | A `cryptoResult` is consumed only if its id/kind/epoch/direction matches an outstanding op. | RFC 008 §5 | M6 |
