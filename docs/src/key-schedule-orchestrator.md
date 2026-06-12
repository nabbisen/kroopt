# The verified key-schedule orchestrator (M15)

M13 built the real key schedule as standalone functions; M14 enriched the crypto
seam and shipped a real provider that satisfies it. In both, the *sequence* of
operations — which op comes next, with which handle as input — lived in test code.
M15 moves that sequence into the verified core, as a pure state machine:
`Kroopt.Core.KeyScheduleDriver`.

## What it is

The orchestrator is the part of the core that *decides the schedule*: given the
result of one crypto operation, it stores the handle that result yields and emits
the next operation, threading handles from each step into the inputs of the next.
It is pure data — it constructs `CryptoOp` values and never performs cryptography,
IO, or FFI — so it lives in the verified core zone alongside `step` and is covered
by the dependency gate (it imports only core types).

The machine runs in **two stages**, matching TLS 1.3's key-derivation timing: the
handshake-traffic keys are installed right after ServerHello, but the
application-traffic keys can only be derived once the server Finished is committed
(the application transcript runs CH..server-Finished). So the chain pauses between
the two:

```
stage 1 (handshake keys):
  awaitShared → awaitEarly → awaitDerivedHs → awaitHandshake
    → awaitServerHs → awaitClientHs → awaitInstallWriteHs → awaitInstallReadHs
    → handshakeKeysInstalled        ← pause

  resumeApplication apTranscript    ← supplies the CH..SF transcript

stage 2 (application keys):
    → awaitDerivedMs → awaitMaster → awaitServerAp → awaitClientAp
    → awaitInstallWriteAp → awaitInstallReadAp → complete
```

`start` takes only the suite, peer share, empty-hash, and the CH..ServerHello
transcript — the application transcript is not yet known — and emits the opening
ECDHE op. Each `advance` consumes the awaited result, records the handle in its
`Handles` table, and emits the next op, until the handshake-key stage finishes and
the machine parks at `handshakeKeysInstalled`. When the server flight has been
committed and the CH..server-Finished transcript is known, `resumeApplication`
supplies it and emits the Derive-Secret that opens the master-secret chain; further
`advance` calls run stage 2 to `complete`. An unexpected result for the current
phase is a typed invariant failure.

## What is proved

`Kroopt.Proofs.KeyScheduleDriver` proves the disciplines the `step` integration
relies on, lifting the audited theorem count to 85:

* **schedule-ops only** (`advance_emits_schedule_ops`,
  `resumeApplication_emits_schedule_ops`) — every operation either stage emits is
  an ECDHE, HKDF-Extract, HKDF-Expand-Label, or traffic-key-install op. Never an
  AEAD, signature, or randomness op. This is what keeps "no plaintext / no
  AEAD-open during key derivation" intact once these emissions are dropped into
  the handshake.
* **monotone progress** (`advance_progress`, `resumeApplication_progress`) — every
  accepted result advances the phase by exactly one rank (the two non-advancing
  phases, `complete` and the `handshakeKeysInstalled` pause, are excluded), so each
  stage is finite and cannot loop.
* **pause and completion are inert** (`advance_pause_inert`,
  `advance_complete_terminal`) — a crypto result delivered at the pause or after
  completion emits nothing and leaves the state unchanged.

All within `{propext, Quot.sound}`; no `sorry`, no new axioms.

## Driven through the real provider

`Tests.ScheduleDriver` (`kroopt-scheduledriver-test`, 12 checks) closes the loop in
both stages. `start` (with only the CH..ServerHello transcript) opens the
handshake-key stage; the orchestrator emits each op, `mkRealProvider` answers it on
real HACL\* crypto threading the arena, and the result feeds back to `advance`
until the machine parks at `handshakeKeysInstalled`. The handshake secrets and the
installed handshake `write_key`/`write_iv` are checked against the RFC 8448 §3
trace at that point. Then `resumeApplication` supplies the CH..server-Finished
transcript and the application-key stage runs to `complete`, where the Master and
application-traffic secrets and all four installed traffic keys (read/write ×
handshake/application) are checked. The schedule logic is verified core code,
interleaved exactly as the handshake will drive it, computing the published trace
against real cryptography.

## The honest boundary (next)

The orchestrator is built, proved, and shown to drive real crypto — but it is **not
yet invoked by `Kroopt.Core.step`**. Wiring it into the live handshake is the next
milestone: `onEcdheDone` and the gating-result dispatch must kick off and pump the
schedule, threading its `State` through the handshake's negotiation state. Because
the handshake's safety proofs are absence-dominated (no plaintext / no
accept / no AEAD-open before `connected`) and the orchestrator is proved to emit
only schedule ops, that integration should preserve them — but it does touch those
proofs, which is why it is sequenced separately. After it, production entropy and
certificate provisioning, then a real handshake against OpenSSL/curl.
