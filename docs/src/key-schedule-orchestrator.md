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

The machine is a single linear chain of fifteen phases, from the ECDHE share
through to the installed application keys:

```
awaitShared → awaitEarly → awaitDerivedHs → awaitHandshake
  → awaitServerHs → awaitClientHs → awaitInstallWriteHs → awaitInstallReadHs
  → awaitDerivedMs → awaitMaster → awaitServerAp → awaitClientAp
  → awaitInstallWriteAp → awaitInstallReadAp → complete
```

`start` emits the opening ECDHE op; each `advance` consumes the awaited result,
records the handle in its `Handles` table, and emits the next op (a single op, or
none at completion). An unexpected result for the current phase is a typed
invariant failure.

## What is proved

`Kroopt.Proofs.KeyScheduleDriver` proves three disciplines, lifting the audited
theorem count to 82:

* **schedule-ops only** (`advance_emits_schedule_ops`) — every operation the
  orchestrator emits is an ECDHE, HKDF-Extract, HKDF-Expand-Label, or
  traffic-key-install op. It never emits an AEAD, signature, or randomness op.
  This is the property the `step` integration will lean on: dropping these
  emissions into the handshake cannot introduce a plaintext emit or an AEAD-open.
* **monotone progress** (`advance_progress`) — every accepted result advances the
  phase by exactly one rank, so the schedule is finite: it reaches `complete`
  after a fixed number of results and cannot loop.
* **`complete` is absorbing** (`advance_complete_terminal`) — once finished,
  further results emit nothing and leave the state unchanged.

All within `{propext, Quot.sound}`; no `sorry`, no new axioms.

## Driven through the real provider

`Tests.ScheduleDriver` (`kroopt-scheduledriver-test`, 11 checks) closes the loop:
the orchestrator emits each op, `mkRealProvider` answers it on real HACL\* crypto
threading the arena, and the result is fed back to `advance` for the next op —
until `complete`. Then every secret the orchestrator collected (read back from the
arena by the handle it stored) and the installed handshake key/IV are compared to
the RFC 8448 §3 trace: ECDHE shared, Handshake and Master Secrets, the server
handshake- and application-traffic secrets, and the installed server-handshake
`write_key`/`write_iv`, with all four (read/write × handshake/application) traffic
keys installed. The schedule logic is now verified core code, and it computes the
published trace when run against real cryptography.

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
