# Changelog

All notable changes to kroopt are recorded here. RFC lifecycle transitions are
governed by [`rfcs/done/000-rfc-lifecycle-policy.md`](rfcs/done/000-rfc-lifecycle-policy.md).

## [Unreleased]

## [0.98.0-dev] — RFC 020 locked for v0.3; SecurityEvent API + metric emission relocated to v0.4 — 2026-06-15

Per architect review (decision **A2 / B2 / lock yes / C1**). RFC 020 moves to `done/`.

### Changed
- **`rfcs/proposed/020` → `rfcs/done/020`.** Status → **Implemented (0.98.0-dev)**. §9 acceptance
  annotated with v0.3 met-status; a new **§10** records the v0.3/v0.4 split:
  - **§10.1 (A2)** — the public subscribable `SecurityEvent` API is *not* added in v0.3 (avoids a
    premature public-API commitment pre-jemmet/RFC 027); its intended content is mapped to the existing
    surfaces (`TlsConn.metadata`/`negotiatedAlpn` for success, `TlsErrorView` for failure, `TraceEvent`
    for the debug trace).
  - **§10.2 (B2)** — metric honesty: the `Metrics` counter logic exists and is tested, but v0.3 does
    **not** claim live driver emission, histograms, aggregation, or export (all v0.4). An optional
    non-public internal wiring of the existing struct is permitted but not required.
  - **§10.3 (C1)** — the public `ErrorCategory` stays intentionally coarse (8 categories); finer §6
    reasons remain internal/debug-only unless a later RFC exposes them.
  - **§10.4** — the relocated v0.4 acceptance criteria (8 items: public event API + jemmet examples,
    stable `HandshakeSummary`, audit events distinct from trace, live counter emission, histogram
    policy, export model, redaction tests for all public surfaces, RFC 027 stability review).
- **`docs/src/operations/event-and-metric-reference.md`** — records that public error categories are
  intentionally coarse and stable, with finer causes kept internal.
- **`rfcs/README.md`** — 020 moved Proposed → Done. **`ROADMAP.md`** — governance order updated (020
  locked v0.3) and an RFC 020 lock note added mirroring the RFC 031/036 notes.

### Scope note
- This locks RFC 020's v0.3 content only. RFC 020 must not be cited as evidence that a public event
  stream or runtime metric emission exists — those are the relocated v0.4 deliverables (§10.4).

Gate: build green; `trace` 19 checks green; hygiene; axioms 102, no `sorryAx`; all SUMMARY links
resolve; no stale `proposed/020` references. Docs/RFC-only change; no `Kroopt/` source, proofs, or
pure-zone code touched (the optional `Metrics`-into-driver wiring was deliberately not bundled with the
lock).

## [0.97.0-dev] — RFC 020 criterion 5: operator event and metric reference — 2026-06-15

Parallel-governance increment building on the trace facility. Documents the operator-facing surface.

### Added
- **`docs/src/operations/event-and-metric-reference.md`** + a new **Operations** section in
  `docs/src/SUMMARY.md`. The reference covers, honestly separating built from planned:
  - the **events emitted today** — the `debug_trace`-gated, secret-free `TraceEvent` taxonomy
    (13 variants), each with when it fires and what it carries (lengths/ids/kinds/categories only);
  - the **redaction guarantee** — what no event can ever contain, enforced structurally;
  - the typed public **error categories** jemmet consumes;
  - the **planned (not-yet-emitted)** metric catalogue, explicitly marked as design so the names are
    stable when they land — kroopt emits no operational counters today.

### Notes
- RFC 020 criterion 5 (operator event/metric reference) is met; the event taxonomy (§3) and redaction
  (§4) are satisfied by the trace facility (`Tests.Trace` CI negatives), and secret-bearing types are
  unprintable by construction (criterion 4). RFC 020 is **not** locked: the §5 public-event-API scope
  (a subscribable structured event stream vs today's diagnostic trace) and actual metric emission
  remain open and want an architect ruling.

Gate: build green; `trace` 19 checks green; hygiene; axioms 102; all SUMMARY links resolve.
Docs/RFC-only change; no `Kroopt/` source, proofs, or pure-zone code touched.

## [0.96.0-dev] — RFC 036 locked (criteria 1/2/4); durable archival relocated to M38 — 2026-06-15

Completes the architect-approved close-out. RFC 036 moves to `done/`.

### Added
- **`docs/src/interop/constrained-vs-browser-grade.md`** (criterion 4) + a new **Interoperability**
  section in `docs/src/SUMMARY.md`. The page draws the interop line honestly — *constrained, tested
  today* (TLS 1.3 server, no HRR, supported-group keyshare required, three live clients
  OpenSSL/Python/curl across handshake/data/graceful-close/rejection, and RFC 8701 GREASE tolerance
  for named-group and cipher-suite values alongside valid ones) vs *browser-grade, not yet claimed*
  (real browsers, edge CHs, h2 end-to-end, ticket/early-data decline, the no-HRR caveat) — claiming
  exactly what is tested and nothing more.

### Changed
- **`rfcs/proposed/036` → `rfcs/done/036`.** Status flipped to **Implemented (0.96.0-dev)** with lock
  framing. Acceptance criterion 3 rewritten: constrained live behaviour is *tested*; **durable
  transcript archival is relocated to M38** as CI/milestone infrastructure. A new §8 records the lock
  and the M38 archival acceptance criteria (committed kroopt-side secret-free canonical traces +
  normalized summaries; ephemeral raw client witnesses; no committed secrets; stable normalization).
- **`rfcs/README.md`** — 036 moved from Proposed to Done; headline-track prose updated (036 locked,
  leaving RFC 015/026 the headline).
- **`ROADMAP.md`** — M38 block updated (036 substance locked; archival is M38's remaining deliverable);
  post-lock order line updated; an RFC 036 lock note added mirroring the RFC 031 lock note.

### Scope note
- This lock covers RFC 036's own scope (criteria 1, 2, 4 + tested constrained behaviour). RFC 036 must
  not be cited as evidence that durable transcript archival exists — that is an M38 deliverable. Live
  jemmet HTTPS E2E and interop breadth remain tracked under RFC 015/026.

Gate: build green; `replay` 18 checks green; hygiene; axioms 102, no `sorryAx`; all SUMMARY links
resolve; no stale `proposed/036` references. Docs/RFC-only change; no `Kroopt/` source, proofs, or
pure-zone code touched (full 27-suite + interop sweep was green at 0.95.0-dev, the last code change).

## [0.95.0-dev] — RFC 036 close-out substantiation: GREASE tolerance + live curl + graceful close — 2026-06-15

Per the architect's close-out review (plan **B / committed-canonical / +close +curl / verify-GREASE**),
this makes every "tested today" interop claim real, ahead of the RFC 036 lock (docs + re-scope, next).

### Added
- **`Tests/Replay.lean`** (now 18 checks) — two committed **GREASE-tolerance** captures, verified
  before claiming (RFC 8701): a GREASE named group (`0x0a0a`) alongside x25519, and a GREASE cipher
  (`0x0a0a`) before `TLS_AES_128_GCM_SHA256`, are each **ignored** — the valid value is selected and the
  handshake reaches full flight. (A ClientHello offering *only* an unknown group still rejects, per the
  0.94 malformed corpus; the difference is precisely "alongside valid.")
- **`scripts/tls-interop.sh`** — a `test_curl_http` scenario: a live **curl** HTTPS GET against the
  reactor's `http` mode, asserting the TLS 1.3 handshake, a 200 body received over TLS, and an
  explicitly-observed **graceful `close_notify`** (RFC 8446 §6.1). ALPN is observation-only — not an
  end-to-end HTTP/2 claim. The constrained live set now spans OpenSSL + Python + curl and
  handshake + data + **close** + rejection.

### Notes
- These are the substantiating tests behind the criterion-4 documentation; the RFC 036 **lock** (the
  docs page + the in-RFC note relocating durable live-transcript archival to M38) is the next
  increment. Durable archival itself (committed canonical secret-free traces + ephemeral raw client
  witnesses + normalization) is an M38 deliverable per the review.

Gate: build green; 27 suites green (incl. `replay`); hygiene; axioms 102, no `sorryAx`; fuzz 20000;
sanitizer clean; live OpenSSL + Python + **curl** interop green (handshake + data + graceful close +
rejection). No `Kroopt/` source, proofs, or pure-zone code touched.

## [0.94.0-dev] — RFC 036 §2 malformed/edge capture corpus — 2026-06-15

Completes RFC 036 acceptance criterion 1: the committed captured-ClientHello corpus now spans
constrained + broad + **malformed**, all replaying deterministically through the pure/fake path.

### Added
- **`Tests/Replay.lean`** (now 16 checks): a `buildExts` builder (full extension blob verbatim) and
  three committed malformed/edge captures, each asserting deterministic rejection
  (`failed illegal_parameter`, **no partial flight**):
  - ClientHello with **no `key_share`** extension;
  - ClientHello with a **duplicated `supported_versions`** extension;
  - ClientHello offering **only an unsupported group** (0xfafa, no x25519).
  Real clients do not emit malformed handshakes, so these are built deterministically rather than
  packet-captured; the existing real openssl/Python captures remain raw committed hex.

### Notes
- RFC 036 acceptance criterion 1 (constrained + broad + malformed corpus, deterministic) is now met.
  The RFC stays Proposed pending criterion 3 (M38 live runs must *archive* OpenSSL/curl transcripts —
  interop runs live and green but does not yet persist artifacts) and criterion 4 (a docs page
  distinguishing constrained from browser-grade interop).

Gate: build green; 27 suites green (incl. `replay`, `correspondence`, `interop`); hygiene; axioms
102, no `sorryAx`; fuzz 20000; live OpenSSL/Python interop green. Tests-only change; no `Kroopt/`
source, proofs, or pure-zone code touched.

## [0.93.0-dev] — RFC 036 §3 debug_trace interpreter wiring — 2026-06-15

Makes the no-secrets trace facility (0.89.0-dev) usable at runtime, completing the §3 slice: a real
handshake can now emit a secret-free diagnostic trace, gated off by default.

### Changed
- **`Kroopt/Conn/Interpreter.lean`** — `RuntimeState` gains `traceEnabled : Bool := false` and
  `trace : List String := []` (both defaulted, off by default). The action fold `execActions` now
  appends `(traceOfAction a).map render` to `RuntimeState.trace` for each executed action **when the
  gate is set** — a passive observation sink that makes no protocol decision and leaves the action
  stream and core transitions untouched (correspondence suite unaffected). Secret-freedom carries
  from the projection: every traced action was already proven to expose only lengths/ids/kinds/codes,
  never secret bytes.

### Added
- **`Tests/Replay.lean`** debug_trace checks (now 13 total): with the gate **off** (the default) a real
  openssl-capture handshake records an **empty** trace (no overhead/leak); with the gate **on** it
  records a non-empty trace carrying real `crypto-call`, `handshake-out`, and `certificate-out` events.
- **`docs/src/architecture/trace-facility.md`** updated: the wiring and gating posture are now in place
  rather than "downstream."

Gate: full build green; 27 suites green (incl. `correspondence`, `interop`); hygiene; deps 37
pure-zone clean; axioms 102, no `sorryAx`; fuzz 20000; sanitizer clean; live OpenSSL/Python interop
green. No proofs or pure-zone code changed.

## [0.92.0-dev] — RFC 036 §2 committed real-client capture corpus — 2026-06-15

Extends the replay bridge with genuine ClientHello captures, so the verified path is exercised
against real client-byte diversity (not just synthetic fixtures) before live sockets.

### Added
- **Committed real captures in `Tests/Replay.lean`** (`kroopt-replay-test` now 11 checks): genuine
  TLS 1.3 ClientHello records captured from `openssl s_client` (a broad default offer, and a
  `-ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519`-constrained one) and Python `ssl` (a
  broad offer carrying SNI `example.com`), replayed through the pure parser + production interpreter
  with deterministic assertions:
  - the broad openssl/Python captures negotiate aes256GcmSha384 / x25519 and produce a server flight;
  - the constrained openssl capture honors the client's CHACHA20 constraint
    (chacha20Poly1305Sha256 / x25519) — real evidence the negotiation tracks the client's offer;
  - a real openssl capture split into 3 fragments reproduces an identical negotiation + flight
    (record reassembly on genuine wire bytes incl. the real extension set and SNI).
  Captures are sanitized (client random/key_share are public handshake values) and committed as hex.

### Changed
- **RFC 036 status**: the committed real-capture corpus is recorded against §2. Remaining for the
  RFC: more malformed/edge captures and the interpreter `debug_trace` wiring.

Gate: full build green; 27 suites green; hygiene; deps 37 pure-zone clean; axioms 102, no `sorryAx`;
fuzz 20000; sanitizer clean; live OpenSSL/Python interop green. No proofs or pure-zone code changed.

## [0.91.0-dev] — RFC 010 locked (ACTIVE → Implemented, → `done/`) — 2026-06-15

Resolves the headline real-socket RFC. No code or proofs changed; this is an RFC-lifecycle
increment. RFC 010's five §12 acceptance criteria are all met and tested, so its `ACTIVE` workflow
label (a pre-`done` "current work item" marker stamped at 0.48.0-dev, not a claim of remaining work)
is flipped to Implemented and the RFC moves `proposed/ → done/`.

### Changed
- **RFC 010 status → Implemented (0.91.0-dev)**, moved to `done/`. Acceptance evidence recorded:
  documented public API with consumption semantics; interpreter without protocol branching
  (`execAction` does not take the core `State`); no iotakt source changes (`Tests.IotaktBinding`);
  bounded queues + progress budgets; partial-write / `wouldBlock` / stale-event coverage
  (`Tests.Conn`); real AF_UNIX handshake to `connected` (`Tests.SocketDriver`); non-blocking
  readiness reactor (`Tests.LiveServerNb`); live OpenSSL/Python interop + app-data round-trip
  (`scripts/tls-interop.sh`). Live-interop **breadth** (RFC 026) and jemmet HTTPS **E2E** (RFC 015)
  continue as their own RFCs — this lock covers RFC 010's own scope only.
- **`rfcs/README.md`, `ROADMAP.md`**: RFC 010 moved Proposed→Done; the `ACTIVE` labels updated to
  Implemented; post-lock headline order refreshed (010 locked; 036 §2/§3 first slices landed; 037
  inbound-alert residue done).

## [0.90.0-dev] — RFC 036 §2 captured-client replay bridge (first slice) — 2026-06-15

Second slice of RFC 036 on the real-wire band: a deterministic replay bridge that exercises
real-shaped ClientHello captures through the verified path before live sockets.

### Added
- **`Tests/Replay.lean`** (`kroopt-replay-test`, 7 checks) — replays ClientHello captures through the
  **pure parser + production interpreter over the fake transport** (the path live sockets use, minus
  syscalls), asserting deterministic negotiation and rejection:
  - a constrained capture negotiates aes128GcmSha256 / x25519 and produces a server flight;
  - the same capture split into 2 and 3 fragments yields a byte-identical negotiation + flight,
    exercising record reassembly/coalescing on real-shaped bytes;
  - a broad capture that additionally offers aes256GcmSha384 deterministically negotiates that suite
    — same client, different offer → different deterministic selection;
  - a TLS-1.2-only capture is rejected cleanly: no negotiation, no flight, never connected (no
    downgrade).
  Captures are sanitized (public randoms/key_shares only) and the server ephemeral is pinned so the
  result is reproducible; the ECDHE/HKDF/signature math is the real HACL\* path.

### Changed
- **RFC 036 status**: §2 replay bridge (first slice) recorded as landed alongside the §3 trace
  facility. Remaining: a fuller committed capture corpus (real `openssl`/`curl` captures + more
  malformed/edge cases) and the interpreter `debug_trace` wiring.

Gate: full build green; 27 suites (incl. `replay`, `trace`) green; hygiene; deps 37 pure-zone clean;
axioms 102 public theorems, no `sorryAx`; parser fuzz 20000; sanitizer clean; live OpenSSL/Python
interop green. No proofs or pure-zone code changed.

## [0.89.0-dev] — RFC 036 §3 no-secrets trace facility (first slice) — 2026-06-15

First forward increment on the unfrozen real-wire band: the diagnostic backbone of the live-interop
milestone (RFC 036 §3). Pure, verification-first, and self-contained.

### Added
- **`Kroopt/Conn/Trace.lean`** — the no-secrets trace facility. `TraceEvent` carries only public
  protocol data (connection/op ids, crypto-op kinds, byte *lengths*, wire code points, alert
  descriptions, close/error *categories*); the pure projection `traceOfAction : OutputAction →
  Option TraceEvent` maps every byte-bearing action to a length and every secret reference to a bare
  event, so **no rendered trace line can carry plaintext, ciphertext, certificate DER, a transcript
  digest, or a secret handle** — secret-freedom is a property of the type's shape, not of a
  redaction pass. `TraceEvent.render` / `traceActions` produce compact secret-free diagnostic lines.
- **`Tests/Trace.lean`** (`kroopt-trace-test`, 19 checks) — per-variant projection/render coverage
  plus the no-secrets centerpiece: a `SECRET` sentinel embedded in `emitPlaintext`, `writeTransport`,
  `writeCertificate`, and a secret-carrying `callCrypto` is shown to never appear in the rendered
  trace, individually and across a mixed action stream.
- **`docs/src/architecture/trace-facility.md`** (+ SUMMARY entry) — the secret-freedom-by-construction
  rationale, what a trace records, and the `debug_trace` gating posture (opt-in, never default).

### Changed
- **RFC 036 status**: §3 trace facility (first slice) recorded as landed; §2 captured-client replay
  bridge and the interpreter `debug_trace` wiring remain.
- **RFC 037 §6 reconciled**: the inbound-alert residue (deterministic alert level/description parsing
  into the close state machine) was already implemented and tested — `Core.RecordPath.onInboundAlert`
  with `Tests.Close` coverage (close_notify → graceful; every other alert → fatal/abortive, no
  response alert; malformed → decode error; no plaintext) — so its status is corrected from
  "deferred" to done. This satisfies the headline-track "037 inbound-alert residue before live
  external-client claims" gate.

Gate: full build green; 26 suites (incl. `trace`) green; hygiene; deps 37 pure-zone clean; axioms
102 public theorems, no `sorryAx`; parser fuzz 20000; sanitizer clean; live OpenSSL/Python interop
green. No proofs or pure-zone code changed.

## [0.88.0-dev] — RFC 031 locked for synchronous correspondence (→ `done/`); async ledger relocated to RFC 040 — 2026-06-15

Cuts the RFC 031 ↔ RFC 040 scheduling knot per architect review. No code or proofs changed; this is
an RFC-lifecycle/governance increment. RFC 031's synchronous production-interpreter correspondence
(landed in substance at 0.47.0-dev) is now formally **locked**, unfreezing the real-wire band; the
async residue that could not be exercised in the synchronous interpreter moves to the band where it
first applies.

### Changed
- **RFC 031 §7 criterion 4 re-scoped to its synchronous line** and the RFC moved `proposed/ →
  done/` (Status: Implemented (0.88.0-dev), synchronous correspondence locked). Criterion 4 is now
  "synchronous crypto-result authorization" — the wrong-kind guard plus the direct §6
  negative-bypass tests (wrong-kind result terminal; no early plaintext emit; no app accept
  before-`connected`/after-close; wrong client Finished rejected), all already landed. A new §7.1
  records the four lock conditions: 031 locks **synchronous** correspondence only; RFC 040 is
  mandatory before production/stable native-secret or async-result claims; live interop may proceed
  on the current interpreter; and 031 must not be cited for duplicate/stale/after-terminal
  async-result behavior.
- **Real-wire band unfrozen** (`rfcs/README.md`, `ROADMAP.md`): with 031 locked, RFC 010 (iotakt
  socket adapter) is the active headline track → RFC 036 → RFC 037 inbound-alert residue → RFC
  015/026 live interop; RFC 030/027/020 run in parallel as governance filler; RFC 040 is the
  stable/v1 follow-up.

### Added
- **RFC 040 §4.4 — async crypto-result ledger (relocated from RFC 031 §5/§4).** RFC 040 now
  explicitly owns the async negative-space: every IO effect justified by a core-authorized action or
  terminal cleanup; every async crypto result correlated to a live op id / expected kind /
  epoch-direction / current generation; duplicate results fatal-or-ignored per policy; stale
  cross-generation results ignored with a metric and no state mutation; results after terminal
  release resources and cannot emit plaintext. §10 records that RFC 040 is mandatory before any
  production/stable native-secret or async-result claim.

## [0.87.0-dev] — traffic-secret C-arena migration decision (D-now / A-later) + RFC 040 — 2026-06-15

Records the architect-reviewed decision on migrating connection-lifetime traffic secrets onto the
C-owned zeroizing arena. No code or proofs changed; this is a governance/documentation increment.
The decision is **defer now, two-interpreter migration later** — keep traffic secrets in the pure
`SecretArena` with documented best-effort zeroization through the pre-stable line, and migrate via a
pure-model + IO-production architecture as a **stable/v1 gate**, sequenced **after RFC 031**.
IO-ifying the single interpreter (which would collapse the proof/runtime correspondence) is
rejected; a partial base-secret migration is not the default path.

### Added
- **`rfcs/proposed/040-native-traffic-secret-arena.md`** (Proposed — **blocked on RFC 031**, target
  stable/v1): the future Option-A contract — two-interpreter architecture with pure↔IO
  correspondence; the handle-in/handle-out production rule (secret bytes never round-trip through
  Lean); secret classes (`ConfigSecret` / `ConnectionSecret` / `EphemeralDerivedSecret`);
  generation-namespaced `SecretHandle` with stale-handle fail-closed; failure-path release/zeroize;
  and sanitizer/leak test requirements. Indexed in `rfcs/README.md`.

### Changed
- **Trust matrix kept as two distinct rows (no longer blurred)** in
  `docs/src/verification/proof-assumptions.md` and `docs/src/verification/threat-model.md`:
  *server private key* = TESTED C-owned zeroization (already migrated); *connection traffic
  secrets* = BEST-EFFORT / tested logical invalidation (Lean-GC byte storage). No production
  zeroization is claimed for traffic secrets until the native arena lands.
- **`docs/src/verification/deferred-scope.md`**: adds the native traffic-secret arena migration as a
  stable/v1-gated deferred item (decision, sequencing after RFC 031, pre-stable vs stable/v1
  posture).
- **`ROADMAP.md` §7**: new cross-cutting decision — secret-memory zeroization is staged by lifetime
  and the two postures stay distinct; the migration is a stable/v1 gate sequenced after RFC 031
  (RFC 040), not an interpreter IO-ification.

## [0.86.0-dev] — RFC 028: security review and vulnerability process (→ `done/`) — 2026-06-15

Establishes kroopt's security process as a concrete deliverable rather than an intention. No
code or proofs changed; this is a governance/documentation increment. RFC 028 meets all of its
§7 acceptance criteria and moves `proposed/ → done/`.

### Added
- **`SECURITY.md`** (repo root): the honest PROVEN / ASSUMED / TESTED / OUTSCOPE scope statement
  (so a report is judged against what kroopt actually claims — e.g. "server does not validate the
  peer chain" is documented scope, not a bug), supported-version policy (pre-1.0: latest `0.x`-dev
  / `main` only), the private report channel (GitHub security advisories), and the rule that a
  security fix is incomplete without a regression test or theorem.
- **`docs/src/security-review-checklist.md`**: the per-milestone review checkpoints (M0–v0.4), the
  ten release blockers each mapped to its enforcement (most are CI-enforced — the no-early /
  no-unauthenticated-plaintext, nonce-uniqueness, fatal-overflow, transcript, and parser-bounds
  proofs via `lake build` + `check-axioms.sh`; parser fuzzing; the ASan/UBSan sanitizer job;
  hygiene for unprintable secrets), the Critical/High/Medium/Low classification, and the triage
  workflow. Added to the mdbook `SUMMARY.md`.

### RFC lifecycle
- RFC 028 → `done/` with `**Status.** Implemented (0.86.0-dev)`; `rfcs/README.md` index updated
  (Proposed → Done; remaining-proposed count eleven → ten).

## [0.85.0-dev] — RFC 037 §4.1: crypto-op budget enforcement — 2026-06-15

Crypto-op allocation is brought into the same budget-enforced `Except` idiom as every other
resource charge, making the `maxPendingCryptoOps` bound real, and the sequence-advance proofs
are restated to the honest *registered-reserves-and-advances* invariant. RFC 037 remains in
`proposed/` — §4.1 is now partially met (outstanding-op **count** is enforced; pending-op
*bytes* and operation *timeout/expiry* are still deferred with the async-crypto work).

### Core
- `State.allocOp` now returns `Except ResourceLimitError (OperationId × State)` and fails with
  `.pendingCryptoOps` when registering another op would exceed `maxPendingCryptoOps`; a CPS
  wrapper `allocOpOrFail` fails the connection closed (`internalError`, fatal) on overflow.
  All 13 registration sites route through it.
- **Clear-on-failure (exactly-once accounting):** the record-path AEAD `.verifyFailed` /
  `.failed` arms of `handleCryptoResultCorrelated` now `clearOp` before failing closed, matching
  the success arms and `handshakeOnGatingResult` (which already retires every handshake-internal
  op on its correlated result). `PendingCryptoOps` is therefore *outstanding work, not history*:
  a completed handshake returns the pending set to zero and the tight cap of 16 stays meaningful.
  No cap change.

### Proofs
- Replaced the (now-false-under-budget) `successful_seal_increments_write_seq` with the
  disjunctive `seal_step_either_registers_and_advances_or_fails_closed` plus derived
  `successful_registered_seal_increments_write_seq` and
  `budget_failed_seal_does_not_advance_write_seq`: a registered seal reserves the current write
  sequence and advances it by one; on allocation failure no op is registered, no plaintext
  crosses, and the connection fails closed without advancing. `successful_open_increments_read_seq`
  is kept and documented — the read advance runs on the authenticated open *result*, not at the
  budget-gated registration, so it is correspondingly unconditional.
- `ActionDiscipline` and `KeySeparation` carry the registered-vs-failed split (budget failure
  emits only fail/alert/reportError; any emitted `callCrypto` still carries correct
  epoch/direction metadata; vacuous on the failed branch).
- New `Kroopt/Proofs/PendingOps.lean`: `correlated_result_clears_op` (retirement removes exactly
  that op) and `clearOp_does_not_grow_pending` (retirement never grows the set — only gated
  `allocOp` can). Axiom gate: 102 public theorems, no `sorryAx`, axioms within
  `{propext, Quot.sound, Classical.choice}`.

### Tests
- `kroopt-crypto-test`: `allocOp` errors at the cap / succeeds below it; an app-send at the cap
  fails closed (terminal + `internalError`, no seal, no sequence advance); a `.verifyFailed` and a
  `.failed` result each clear their op and fail closed.
- `kroopt-handshake-test`: the synthetic trace is driven through the production correlation
  dispatcher (`handshakeOnGatingResult`, which retires the answered op) instead of the transition
  functions directly, so it models crypto-op lifetime — it passes at the tight cap of 16 and
  asserts a completed handshake leaves **zero** ops pending.

## [0.84.0-dev] — RFC 037 §6: inbound alert parsing (close_notify vs. fatal) — 2026-06-15

Inbound TLS 1.3 alerts are now parsed and dispatched deterministically instead of being
collapsed to a graceful close. Previously **every** inbound alert — including a peer's *fatal*
alert — was treated as `close_notify` and routed to a graceful close; a fatal alert now fails
the connection. (RFC 037 §6 / RFC 8446 §6.2; RFC 037 remains in `proposed/` — §4.1 crypto-op
budget enforcement is still pending.)

### Core
- New `onInboundAlert` (`Kroopt/Core/RecordPath.lean`) decodes the two-byte alert
  `[level, description]` and dispatches: `close_notify` (description `0`) begins a graceful
  peer close (unchanged); **any other alert is fatal** in TLS 1.3 regardless of the level byte
  — the connection moves to `failed`, records the received description in
  `closeState := fatalReceived`, and tears down abortively *without* sending a response alert
  (the peer has already aborted). A payload that is not exactly two bytes is a decode error.
- All three inbound-alert sites (one plaintext, two encrypted/`aeadOpened`) now route through
  `onInboundAlert`; the deferred "full policy at M9" stub is retired.
- New total decoder `AlertDescription.ofByte` (`Kroopt/Error.lean`) maps standard alert codes
  to descriptions for recording the received alert.

### Proofs
- The no-unauthenticated-plaintext headline (`buffered_plaintext_authenticated` /
  `buffered_plaintext_provenance`) is preserved across the new path via
  `onInboundAlert_no_new_plaintext` (the handler never *newly* buffers plaintext — it clears
  `pendingPlainOut` or leaves it untouched). Action-discipline (`no_emit` / `no_accept`) is
  preserved via `onInboundAlert_no_emit` / `onInboundAlert_no_accept`; the crypto-op
  separation/nonce proofs unfold the handler to discharge its concrete leaves. All new lemmas
  are private — the axiom gate still audits **98** public theorems, no `sorryAx`.

### Tests
- `kroopt-close-test` (**23**, +4): inbound fatal alert → terminal + `fatalReceived` +
  abortive `closeTransport`; a non-`close_notify` alert is never a graceful close; a malformed
  (non-two-byte) alert is a decode error; `AlertDescription.ofByte` decodes known codes and
  rejects unknown ones. The existing inbound-`close_notify` → `receivedCloseNotify` check is
  unchanged.

## [0.83.0-dev] — RFC 039 Issue 3 hygiene: fatalize defensive crypto-failure arms — 2026-06-15

Closes the deferred hygiene follow-up from the 0.82.0-dev closure review (RFC 039 Issue 3).
The defensively-unreachable failure arms of `handshakeOnGatingResult` now fail closed instead
of silently no-op, so a future direct caller cannot turn a crypto failure into a no-op.

### Core
- `handshakeOnGatingResult` `.verifyFailed` / `.failed e` arms changed from `.ok (s, [])` to
  `hsFail …`, mirroring the live caller's mapping (`.verifyFailed → bad_record_mac`;
  `.failed e → alertForCryptoFailure e`, i.e. `peerInvalidKeyShare → illegal_parameter`, else
  `internal_error`). These arms remain unreachable in practice — the sole caller
  (`handleCryptoResultCorrelated`) consumes both fatally first — but they are now fail-closed
  by construction.

### Proofs
- Added private `hsFail_no_emit` / `hsFail_no_accept` (`hsFail` emits only `failWithAlert` +
  `reportError`, never application plaintext) and threaded them into
  `handshakeOnGatingResult_no_emit` / `_no_accept`, which now cover the fatalized arms. No
  public theorem added — the axiom gate still audits **98** public theorems, no `sorryAx`,
  axioms within the allowlist.

### Tests
- `kroopt-model-test` (**11**, +2): `handshakeOnGatingResult` routed a provider failure or a
  verify failure directly now yields a terminal state and a fatal alert — never a no-op.


## [0.82.0-dev] — RFC 039 closure-review follow-up (crypto-failure taxonomy + docs) — 2026-06-15

Post-closure hardening from the architect's review of the RFC 039 closure questions. RFC 039
stays closed in `done/`; this release applies the three decisions. No proof changed (the axiom
gate still audits 98 public theorems).

### Issue 1 — typed crypto-failure taxonomy (alert correctness)
A peer-supplied key_share that passes wire-shape parsing but is rejected by the provider (an
off-curve / point-at-infinity P-256 point) is **attacker input, not a server fault**, and now
fails the handshake with `illegal_parameter` rather than `internal_error`.
- New `CryptoError.peerInvalidKeyShare` (`Kroopt/Error.lean`); `alertForCryptoFailure` maps it
  to `illegal_parameter`. `handleCryptoResultCorrelated` now routes a `.failed e` through
  `alertForCryptoFailure` (peer-invalid → `illegal_parameter`; genuine provider/shim fault →
  `internal_error`).
- `RealProvider` ecdheP256 classifies the failure: a `none` shared secret **with a valid server
  ephemeral public** isolates the fault to the peer point (`peerInvalidKeyShare`); an empty
  server public is a server-ephemeral fault (`providerInternal`).
- Tests: `kroopt-realprovider-test` (**35**, +1) — an off-curve P-256 point is classified
  `peerInvalidKeyShare`; `kroopt-e2e-test` (**33**, +2) — the core maps a peer-invalid ECDHE
  failure to `illegal_parameter` and a genuine provider fault to `internal_error`. Composed,
  these establish off-curve point → fatal `illegal_parameter` end-to-end.

### Issue 2 — `namedGroups` ordering (documentation)
Confirmed `EndpointConfig.namedGroups` is an **unordered allow-list**; server preference is
fixed by `Core.groupPreference` (x25519 before secp256r1). Documented explicitly in
`architecture/handshake.md` and `architecture/config-cert.md`: list order is ignored, and
`[secp256r1, x25519]` is the same policy as `[x25519, secp256r1]`. Per-endpoint ranking, if
ever wanted, is a separate field, not a reinterpretation of `namedGroups`.

### Issue 3 — defensive unreachable arms (hygiene)
The unreachable `.failed`/`.verifyFailed` arms in `handshakeOnGatingResult` (the sole caller
`handleCryptoResultCorrelated` consumes both fatally first) are now marked as
defensively-unreachable with an explicit instruction to fatalize if ever called directly. Per
the review, fatalizing now (Option A) was deferred to avoid non-trivial churn in
`handshakeOnGatingResult_no_emit` / `_no_accept`; a hygiene follow-up will fatalize them with
the supporting `hsFail` action-freeness lemmas.

### Docs
- `architecture/handshake.md`: corrected the alert-mapping paragraph (peer-rejected point →
  `illegal_parameter`, not `handshake_failure`); added the allow-list ordering clarification.
- `crypto/crypto-ffi-contract.md`: ECDH-rejection now distinguishes `peerInvalidKeyShare`
  (`illegal_parameter`) from a genuine fault (`internal_error`).


## [0.81.0-dev] — RFC 039 finalized (§4.9 tracing, §8.12/§8.14/§8.16 acceptance) → done/ — 2026-06-14

Closes RFC 039. The remaining acceptance items land — safe negotiation tracing, the P-256
point-validation tests (including off-curve provider rejection), alert determinism, and the
x25519-only-listener interop run — and the RFC moves to `done/`. No verified-core logic
changed this release; the work is observability, tests, an interop driver mode, and docs.

### Core — safe negotiation tracing (RFC 039 §4.9)
- New `NegotiationTrace` (`Kroopt/Core/Handshake.lean`): an opt-in, redaction-safe view of a
  group negotiation carrying endpoint groups, client **offered group ids**, the selected
  group, and a rejection *category*. It is **bytes-free by construction** — the structure has
  no `ByteArray` field, so raw `key_share` bytes and the ClientHello blob can never appear in
  a trace. `NegotiationTrace.ofClientHello` collapses each offered `(group, share)` to its id
  (dropping the share); `NegotiationTrace.render` emits group ids + selected id + category only.

### Tests
- `kroopt-e2e-test` (**31**, +9): §8.12 P-256 `key_share` with a bad prefix rejected; with a
  bad length rejected; §8.14 alert determinism — no-overlap → `handshake_failure`, duplicate
  group / `supported_groups`-omission / malformed P-256 → `illegal_parameter` (the e2e `Driver`
  now captures emitted alerts); §4.9 trace surfaces the selected and endpoint/offered group ids
  and never leaks a raw `key_share` byte (a `0xBE` share marker is absent from the rendering).
- `kroopt-hacl-test` (**56**, +1): §8.12 — a 65-byte, `0x04`-prefixed but **off-curve** P-256
  point is rejected fail-closed (`none`) by HACL's on-curve check; no shared secret is fabricated.

### Interop (RFC 039 §8.16)
- The blocking live server gains an `x25519-only` policy mode; `scripts/tls-interop.sh` (**21**,
  +1) now starts an x25519-only listener and asserts an OpenSSL `-groups P-256` client is
  refused (the server reaches a failed phase, never `connected`) — the capability-gap closure
  confirmed end-to-end over the wire, with no HRR.

### Documentation (RFC 039 §9)
- `architecture/handshake.md`: corrected the "X25519-only" framing; added a **Named-group
  selection** section (three-layer model, canonical rule, `selectGroup`, the §5 proofs,
  `supported_groups` consistency, layered P-256 validation, alert mapping, redaction-safe tracing).
- `crypto/crypto-ffi-contract.md`: replaced the stale "group policy is a structural follow-up"
  note with the now-load-bearing three-layer model + P-256 point-validation contract.
- `verification/theorem-inventory.md`: added the RFC 039 PROVEN subsection (four theorems);
  corrected the audited public-theorem count to **98**.

### RFC lifecycle
- RFC 039 status → **Implemented (v0.81.0-dev)**; moved `proposed/` → `done/`; `rfcs/README.md`
  index and intro updated.


## [0.80.0-dev] — RFC 039 §4.6 (supported_groups / key_share consistency) — 2026-06-14

The last negotiation-boundary feature of RFC 039: the parser now enforces consistency
between the `key_share` and `supported_groups` extensions (RFC 8446 §4.2.8 / RFC 039 §4.6).

### Parser (RFC 039 §4.6)
- New `supportedGroupIds` reads the `supported_groups` extension (0x000a) as an `Option`
  (absent vs present-but-empty are distinct).
- `findOfferedKeyShares` now rejects a ClientHello in which **any** offered `key_share`
  group id is absent from a *present* `supported_groups` — a `key_share` for an omitted
  group is a contradiction (illegal parameter), so the core never selects such a group. When
  `supported_groups` is absent, `key_share` remains authoritative (the constrained no-HRR
  compatibility profile). A group listed in `supported_groups` with no usable `key_share` is
  simply not selectable under no-HRR and surfaces as a clean handshake failure.

### Tests
- `kroopt-e2e-test` (**22**, +2): a `key_share` group omitted from `supported_groups` is
  rejected; `supported_groups` present with no usable `key_share` fails cleanly (no HRR).
- Live interop unchanged (20 checks): real OpenSSL/Python clients send a `supported_groups`
  that contains their `key_share` group, so the consistency check accepts them.

### Remaining for RFC 039 → done/
safe negotiation tracing (§4.9 + `traceRedactsKeyShareBytes`), the P-256 point-validation
tests (§8.12, incl. the off-curve provider-rejection case), alert-determinism (§8.14), the
x25519-only-listener interop run (§8.16), and the doc refresh (§9).

## [0.79.0-dev] — RFC 039 §5.2 completion (no-disallowed-group proof) + selection-test breadth — 2026-06-14

Completes the verification dimension of RFC 039 (acceptance item #17): all three §5
theorems now build clean within the axiom allowlist.

### Proofs (RFC 039 §5.2)
- `onClientHello_selectedGroup_allowed`: when `onClientHello` succeeds into
  `requestedServerRandom`, the recorded `selectedGroup` is `some g` with `g` in the resolved
  endpoint's policy — the selectedGroup half of the §5.2 non-event.
- `no_disallowed_group_crypto_op` (the P-256 case, the only one two groups can violate):
  with secp256r1 outside the endpoint policy, no `ecdheP256` op is ever emitted on the
  `onClientHello → onServerRandomDone` path. Composes `onClientHello_selectedGroup_allowed`
  (group never reaches `selectedGroup`) with `ecdhe_op_matches_selected_group` (op matches the
  recorded group). Axiom audit now covers **98** public theorems.

### Tests (RFC 039 §8)
- `kroopt-e2e-test` (**20**, +2): unknown group dropped while the recognized secp256r1 share
  is selected (§8.9); duplicate secp256r1 `key_share` rejected as malformed (§8.10, the P-256
  companion to the x25519 duplicate case).

### Remaining for RFC 039 → done/
supported_groups/key_share consistency (§4.6, a parser feature), safe negotiation tracing
(§4.9), the P-256 off-curve provider test and alert-determinism test (§8.12/§8.14), the
x25519-only-listener interop run (§8.16), and the doc refresh (§9).

## [0.78.0-dev] — RFC 039 Stages 4–5 (core group selection + authorization proofs) — 2026-06-14

This closes the live gap left after Stages 2–3: the endpoint `namedGroups` policy was
*validated* at startup but not *enforced* on selection, so an `[x25519]`-only endpoint did
not actually restrict negotiation. Stage 4 moves ECDHE group selection out of the parser and
into the verified core, gated on the resolved endpoint's policy; Stage 5 proves the
selection is authorized.

### Core selection (Stage 4, RFC 039 §4.3)
- Parser no longer pre-selects a group. `findKeyShare` is replaced by `findOfferedKeyShares`,
  which surfaces **all** recognized offered shares (`ValidClientHello.offeredShares :
  List (NamedGroup × ByteArray)`, client order) and **rejects duplicate group ids** as a
  malformed ClientHello (`hasDupGroupIds`, RFC 8446 §4.2.8 / RFC 039 §4.5).
- New core primitives `groupPreference := [.x25519, .secp256r1]`, `shareFor?`, and the total
  `selectGroup` (no `get!`): it walks the server preference and takes the first group that is
  **both** endpoint-allowed and client-offered. `onClientHello` calls it against the resolved
  endpoint's `namedGroups`; no overlap ⇒ clean `handshake_failure` (§4.8). A secp256r1-only
  client now meets an `[x25519]`-only endpoint with a refusal instead of a P-256 negotiation.

### Authorization proofs (Stage 5, RFC 039 §5)
- `selectGroup_authorized` (§5.1): any group `selectGroup` returns is both `∈ allowed` and
  backed by a share `∈ offered` — no path picks a group outside policy or fabricates a share.
- `ecdhe_op_matches_selected_group` (§5.2): a P-256 ECDHE op is emitted by `onServerRandomDone`
  only when the recorded `selectedGroup` is `secp256r1`.
- Five existing proofs threaded through the new selection branch (`onClientHello_legal`, the
  `hs_no_emit`/`hs_no_accept`/`hs_no_aeadOpen` handshake lemmas, and RecordPath's
  `onClientHello_pp`). Axiom audit now covers **96** public theorems (whitelisted axioms only).

### Tests
- `kroopt-e2e-test` (**18**, +4): both-groups-offered prefers x25519 over client order;
  duplicate `key_share` rejected; **x25519-only endpoint refuses a secp256r1-only client**
  (policy enforced); and that refusal never records a negotiated P-256 group.

### Tooling
- `scripts/check-axioms.sh` theorem-name grep widened to accept Lean identifier characters
  (`?!'`) so `?`-named public theorems are audited rather than silently aborting the gate.

## [0.77.0-dev] — RFC 039 finalized + Stages 2–3 (endpoint group policy + validation) — 2026-06-14

RFC 039 (Named-Group Policy and Selection Enforcement) is approved-for-implementation
after two review rounds; this ships its first implementation increment — the
configuration-side, staying entirely out of the verified core and parser. The group
dimension of the capability model is now load-bearing.

### RFC
- `rfcs/proposed/039-…` revised to **rev-3**: incorporates the architect's rev-2 review
  (normalization/duplicate policy, supported_groups consistency, P-256 validation contract,
  alert mapping, safe tracing, crypto-op-consistency proofs, derive-and-enforce hash) and
  the two merge clarifications (total `selectGroup` with no `get!`; explicit
  absent-`supported_groups` compatibility-policy note) plus the error-taxonomy fix.

### Config policy + validation (Stages 2–3)
- `EndpointConfig.namedGroups : List NamedGroup := [.x25519, .secp256r1]` (RFC 039 §4.1).
  `Inhabited` is now hand-written so `(default : EndpointConfig)` — and every
  `{ default with … }` site — gets the real non-empty default rather than the `[]` that
  `deriving` would supply.
- `CapabilityError` gains `.emptyGroupPolicy` and `.duplicateNamedGroup`.
- `ConfigCheck`: `requiredCryptoOfServerConfig` now populates `groups` from each endpoint's
  `namedGroups` and **derives** `hashAlgorithms` from the configured suites
  (`deriveHashesFromSuites`); `validateServerConfigCapabilities` first normalizes each
  endpoint's group policy (`normalizeNamedGroups` — reject empty/duplicate) and then runs
  the four-dimension capability subset check. The previously inert `groups := []` /
  `hashAlgorithms := []` are gone; all four dimensions are enforced.

### Tests
- `kroopt-capabilities-test` (**14**): unsupported endpoint group → `.unsupportedGroup`;
  empty policy → `.emptyGroupPolicy`; duplicate policy → `.duplicateNamedGroup`; the default
  `[x25519, secp256r1]` endpoint validates against the real provider **and** is rejected by
  an x25519-only provider (proving endpoint-policy ⊆ provider-capability is load-bearing).

### Behaviour unchanged this increment
- Selection still happens in the parser; the `namedGroups` *policy gate on selection* and
  the selection-authorization proofs are the next increment (RFC 039 §4.3/§5, Stages 4–5).
  Existing configs/fixtures/live servers pick up the `[both]` default and continue to
  validate and negotiate exactly as before (94 theorems, 25 suites, fuzz, and interop —
  including the forced P-256 runs — all green).

## [0.76.0-dev] — secp256r1 capability honesty (review Stage 1 / Option B) — 2026-06-14

Closes the immediate half of the secp256r1 capability-gap review (Option C, B-now):
the advertised provider capability now matches actual P-256 negotiation behaviour, and
the path is tested. The structural follow-up (endpoint group policy + a "selected group
is authorized" proof) is captured as an RFC for Stage 2–5.

### Capability advertisement (`Kroopt/Crypto/Provider.lean`)
- `realCapabilities.groups` is now `[.x25519, .secp256r1]`. This is honest, not an
  over-claim: the provider computes a real, NIST-CAVP-validated P-256 ECDH shared secret
  (`Hacl_P256_ecp256dh_r` via `kroopt_ffi_p256_shared`), so the binary genuinely performs
  both groups. (Whether a *listener* should restrict to a subset is the Stage 2 endpoint
  policy decision, not a provider-capability question.)

### Tests
- `kroopt-e2e-test` (**14**): a secp256r1-only ClientHello (group 0x0017, 65-byte
  uncompressed point) drives the full handshake — the core selects P-256, emits
  `ecdheP256`, reaches `connected`, and records `selectedGroup = secp256r1`.
- `scripts/tls-interop.sh`: forced `-groups P-256` OpenSSL scenario on both the blocking
  and reactor drivers — full TLS 1.3 handshake + app-data round-trip — alongside the
  existing x25519 runs. (`test_openssl` gained a groups parameter.)

### Docs
- `crypto-ffi-contract.md` / `proof-assumptions.md`: corrected to state X25519 **and
  secp256r1** are advertised (the audit had documented the pre-Stage-1 x25519-only set).

### Known follow-up (RFC, Stage 2–5)
- `realCapabilities.groups` is still declarative: `requiredCryptoOfServerConfig` hardcodes
  `groups := []`, `EndpointConfig` has no group field, and the parser selects the group
  with no capability/policy gate. Making the group dimension load-bearing (endpoint
  `namedGroups`, populated `req.groups`, core-level selection constrained to the allowed
  set, and a proof that the selected group is authorized) is the next RFC. Per the review,
  the core theorem proves `g ∈ clientOffered ∧ g ∈ endpointAllowed`; `endpointAllowed ⊆
  providerCaps` is discharged at config validation, keeping the verified core
  provider-agnostic. The parallel inert `hashAlgorithms := []` is folded into the same RFC.

### Audit (5-dimension review) — 2026-06-14

A review of (1) done-RFC fulfillment, (2) dead code, (3) tests vs requirements/design,
(4) code vs tests, (5) docs vs code. No code behavior changed; documentation drift fixed.

- **Dead code**: a definition-level scan flagged 10 single-reference defs; on inspection
  all are planned/future/API surface (RFC 007 §5 transcript-bound-input makers; RFC 003
  `BoundedBytes.ofBytes?`; RFC 020 observability `recordFailure`/`recordAlertSent`/
  `redactedSummary`; the documented `alertForUnexpectedMessage`; `isPlaintextAccept` as the
  accept-side companion to the proof-used `isPlaintextEmit`; `committedLength`/`isReleased`
  introspection). **None removed** — none is actually useless.
- **Docs fixed**: `crypto-ffi-contract.md` and `proof-assumptions.md` claimed the real
  provider "never claims AES-GCM/SHA-384" and that an "AES-GCM … config is rejected" — both
  false since the AES suites + SHA-384 landed; corrected (while keeping the still-true fact
  that P-256/ECDSA/RSA are not advertised in the default profile). `key-schedule.md`
  "SHA-256 suite" → hash-parameterized SHA-256/384. Stale theorem counts (87/78) → 94.
- **Open finding (advertise-vs-behave gap)**: `realCapabilities.groups = [.x25519]`, but the
  ClientHello parser accepts secp256r1 unconditionally (`x25519.orElse p256`) and the
  handshake performs P-256 ECDHE for it — so the negotiable group set exceeds the advertised
  one (safe direction, under-advertised), and no negotiation-level test pins the secp256r1
  path. Resolve by either gating group selection on the advertised/config set or advertising
  secp256r1 + adding a P-256 negotiation test. Left as a maintainer decision (changes
  negotiation behavior). The ECDSA/RSA signature schemes are, by contrast, deliberately
  rejected-and-tested (`Tests/Capabilities` asserts `realRejectsEcdsa`).
- **Still outstanding (framing, not auto-fixed)**: `theorem-inventory.md` running totals stop
  at ~52 (M9/M10) and don't reach 94; `handshake.md`/`native-crypto.md`/`third-party.md` still
  frame crypto as the ChaCha20-only "constrained profile". A broader doc refresh, not a
  one-line fix.

## [0.75.0-dev] — Sign-by-handle for all cert key types (ECDSA-P256, RSA-PSS) — 2026-06-14

Completes the C-resident private-key mechanism for every certificate signature scheme: the
ECDSA-P256 scalar and the RSA-PSS private exponent `d` can now be signed *by handle*, like the
Ed25519 key in 0.74, so no cert private key need ever live on the Lean heap.

### Sign-by-handle (`Kroopt/Native/kroopt_ffi.c`, `Kroopt/Crypto/Hacl.lean`)
- `kroopt_ffi_ecdsa_p256_sign_h(m, keyId, k)` and `kroopt_ffi_rsapss_sign_h(n, e, dId, salt, msg)`
  read the secret scalar / `d` from the arena slot inside C; the public `(n, e)` and the ephemeral
  nonce/salt stay caller arguments. Both fail closed on an absent/wrong-size handle.
- Lean: `ecdsaP256SignRawH` / `ecdsaP256SignDerH` and `rsapssSignRawH` / `rsapssSignH`.

### Provider (`Kroopt/Crypto/RealProvider.lean`)
- `RealCryptoConfig.ecdsaKeyHandle` / `rsaKeyHandle` (default `0`), mirroring `certKeyHandle`. The
  ECDSA and RSA `submit` branches sign by handle when set, else fall back to the byte fields.

### Tests
- `kroopt-nativesecret-test` (**10**): adds "ECDSA-P256 sign-by-handle produces a verifying
  signature" and "RSA-PSS sign-by-handle produces a verifying signature" (scalar / `d` resident only
  in C, signature verified against the public key).

### A soundness boundary, made explicit
- The sign-by-handle functions are `opaque` (pure-typed) so the pure `submit` can call them, which
  is valid only under the **load-once, stable-until-shutdown** invariant — a config key is written
  once and never signed-after-release. An exploratory "released cannot sign" check exposed the edge:
  two `signH` calls with *identical* arguments are one pure expression to Lean, so the optimizer may
  reuse the pre-release value. That behavior is out-of-invariant (production never signs after
  release), so the check was removed as ill-founded; the key's wipe-on-release is proven soundly at
  the arena level instead (`zeroize` → zeros, read-after-release → empty). The opaque declarations
  document the invariant.

### Status
- All three cert key types can now reside only in the C zeroizing arena. The Ed25519 path is wired
  and OpenSSL/Python-validated end-to-end (0.74); ECDSA/RSA are mechanism-complete and unit-validated
  (their provisioning — loading the fixture/SNI keys into the arena, including in the separate iotakt
  driver — is the remaining wiring). 94 theorems unchanged; all 25 suites green; fuzz clean.
  Connection-lifetime traffic secrets remain on the pure Lean arena — migrating them requires making
  the pure interpreter drive-loop IO, a deliberate architectural change (it trades the pure-drive-loop
  correspondence property) best taken as its own decision rather than folded in here.

## [0.74.0-dev] — Server private key resident in the C zeroizing arena (sign-by-handle) — 2026-06-14

The integration half of RFC 037 §3's secret-arena work: the highest-value durable secret — the
server's Ed25519 certificate private key — now lives **only** in the C-owned zeroizing arena and is
signed *by handle*, so the key never enters the Lean heap after load and is wiped on shutdown. This
is the design's specified model (§9.10: "config-lifetime private keys are owned by the secret arena
and referenced by kroopt"), validated end-to-end against real clients.

### Sign-by-handle
- `Kroopt/Native/kroopt_ffi.c`: `kroopt_ffi_ed25519_sign_h(keyId, msg)` reads the key from the arena
  slot inside C, signs with HACL, and returns the signature — the key bytes never cross into Lean.
  Fails closed (empty result) if the handle is absent/released or the stored key is not 32 bytes, so
  a wiped key cannot sign.
- `Kroopt/Crypto/Hacl.lean`: `ed25519SignH (keyId) (msg)`. `opaque` because a config-lifetime key is
  loaded once and released only at shutdown, so the arena read is referentially transparent in
  practice; the trust note documents it.

### Lifecycle wiring
- `Kroopt/Crypto/RealProvider.lean`: `RealCryptoConfig.certKeyHandle` (default `0`). When non-zero
  the provider signs CertificateVerify by handle; `0` falls back to `certPrivate` bytes (the
  deterministic test path), so existing fixtures are unchanged.
- `Kroopt/Crypto/Provision.lean`: `provisionRealConfig` loads the Ed25519 key into the arena and
  leaves `certPrivate` empty — the durable config holds a handle, not key bytes.
- `Tests/LiveServer.lean`: the live server loads its key into the arena, signs by handle, and
  releases (wipes) it on shutdown.

### Validation
- `kroopt-nativesecret-test` (+2, **9**): an Ed25519 key resident only in C signs by handle and the
  signature verifies against the public key; after `release`, the same handle can no longer produce
  a verifying signature (the durable key is gone).
- `scripts/tls-interop.sh`: the full OpenSSL + Python matrix (all three suites, both drivers) passes
  with the key C-resident — the clients verify the CertificateVerify against the cert's public key,
  so sign-by-handle produces correct signatures real clients accept.
- `Tests/Provision.lean`: updated to assert the key now lives in the arena (config key empty, handle
  set, arena read-back equals the seed).

### Trust posture
- The server private key's durable home is now zeroizable C memory, wiped on shutdown — the
  end-to-end posture for this secret is no longer "best-effort Lean ByteArray that is never wiped."
  Connection-lifetime traffic secrets still route through the pure Lean arena (the production-claim
  gate's remaining secret-memory item), as do ECDSA/RSA key handles. 94 theorems unchanged; all 25
  suites green; arena clean under ASan/UBSan.

## [0.73.0-dev] — C-owned zeroizing secret arena (native primitive) — 2026-06-14

The first half of the one item gating an honest "production-ready" claim (RFC 037 §3): a real
**C-owned zeroizable secret store**, where a secret's durable home is malloc'd C memory that is
actually overwritten on release rather than left for the GC. The existing `SecretArena` is a pure
Lean `List (UInt64 × ByteArray)` — ideal for determinism and proof visibility, but its bytes are
never wiped. This lands the native store the requirements (§13) and RFC 037 name as the fixed target,
following the project's primitive-then-integrate cadence: the store + its wipe proof + sanitizer
coverage now; wiring the production interpreter's secret lifecycle onto it next.

### Native store (`Kroopt/Native/kroopt_ffi.c`)
- A process-global registry of malloc'd secret buffers addressed by a **monotonic, never-reused**
  u64 id (so a freed id reads as absent — no ABA / use-after-free of a recycled id; single event
  loop, no locking). `kroopt_ffi_secret_alloc/read/zeroize/release/live_count`. `release` and
  `zeroize` overwrite the buffer through a **volatile** pointer (not dead-store-eliminated) before
  `release` frees it. `release` is idempotent, so a double release is a safe no-op.

### Lean binding (`Kroopt/Crypto/NativeSecret.lean`)
- IO externs `alloc`/`read`/`zeroize`/`release`/`liveCount` over an opaque `SecretId`; the Lean side
  holds only the id, never the bytes' durable home. Lives in the impure Crypto zone (dependency gate
  clean — the pure verified core is untouched).

### Tests
- `kroopt-nativesecret-test` (new, **25th** suite, 7 checks): the decisive one is that `zeroize`
  overwrites the live buffer with zeros — observable while the slot is still allocated, so the wipe
  is *real*, not asserted. Plus round-trip, release-removes-slot, safe double release, never-reused
  ids, and no-leak via `liveCount`.
- `scripts/sanitizer-check.sh`: the harness now exercises the arena (alloc/read/zeroize/release,
  double release, read-after-release) under ASan/UBSan — clean, with no double-free or UAF and
  `live_count` back to zero.

### Trust posture
- `docs/.../proof-assumptions.md` updated: the zeroizable home is now built and proven to wipe (not
  merely specified), but the live handshake still routes secrets through the pure Lean arena until
  the lifecycle is wired, so the end-to-end posture stays *best-effort, tested, not
  zeroization-guaranteed*, with no production zeroization guarantee yet. 94 theorems unchanged; all
  25 suites green; parser fuzz clean.

### Remaining for the production claim
1. Replace the live-path arena's `ByteArray` storage with `NativeSecret` handles (resolving the
   pure-`submit`/IO seam), so durable connection/config secrets — traffic secrets and the server
   private key — are wiped on every terminal path end-to-end.
2. The rest of RFC 037's production gate (config-sourced limits, crypto-op bounds) and the
   process/maturity RFCs (security review, perf benchmarks, production runbook).

## [0.72.0-dev] — AES-256-GCM-SHA384 negotiated end-to-end + OpenSSL-validated — 2026-06-14

`TLS_AES_256_GCM_SHA384` now negotiates and serves a full TLS 1.3 handshake plus application-data
round-trip against **real OpenSSL** — on both the blocking and non-blocking reactor drivers. This
completes the third and last TLS 1.3 cipher suite (all of AES-128-GCM, AES-256-GCM, and
ChaCha20-Poly1305 are now interop-validated) and is the payoff of the SHA-384 primitive (0.70) and
hash-parameterized schedule (0.71) work.

### Core (the proof-touching step — proofs intact)
- `Kroopt/Core/CipherSuite.lean`: added a pure `HashAlgorithm.digestLen` (32/48) so the verified
  core can size HKDF ops without the FFI-zone `KeySchedule.hashLen`.
- `Kroopt/Core/KeyScheduleDriver.lean`: the driver now emits every HKDF-Extract / Expand-Label op
  under `suite.hashAlg` and `digestLen` instead of hardcoded `.sha256`/`32` (the `expand` helper
  takes the hash). Added the `emptyHashSha384` constant and `emptyHashFor` so the two
  Derive-Secret(_, "derived") steps use the suite's empty hash. The driver's proofs
  (`Kroopt/Proofs/KeyScheduleDriver.lean`) match the op constructors with the alg/length as
  wildcards, so schedule-ops-only / monotone-progress / absorbing-complete are unaffected.
- `Kroopt/Core/Handshake.lean`: `onClientHello` sets the transcript's `hashAlg` to the negotiated
  suite's hash, and the post-ECDHE start passes the suite's empty hash. The Finished ops already
  carried `s.transcript.hashAlg`, so they now compute under SHA-384 for the AES-256 suite.

### Interpreter (impure execution — no proof surface)
- `Kroopt/Conn/Interpreter.lean`: `resolveCryptoTranscript` hashes the core-carried transcript
  prefix under the op's `HashAlgorithm` (and, for the alg-less CertificateVerify op, the negotiated
  suite's hash looked up from the installed handshake keys) rather than hardcoded SHA-256.

### Negotiation
- `Kroopt/Parse/Handshake.lean`: `suiteOfU16` recognizes `0x1302` (TLS_AES_256_GCM_SHA384).
- `Kroopt/Crypto/Provider.lean`: `realCapabilities` advertises `aes256GcmSha384` and `sha384`.

### Tests
- `kroopt-correspondence-test` (+1, **34**): a SHA-384 Finished op is shown to be hashed with
  SHA-384 (48-byte digest), not SHA-256.
- `kroopt-capabilities-test`: the real profile/provider now *accept* AES-256-GCM-SHA384 (was a
  rejection assertion).
- `scripts/tls-interop.sh`: AES-256-GCM-SHA384 added to the OpenSSL matrix on both drivers — OpenSSL
  reports `Cipher is TLS_AES_256_GCM_SHA384`, the handshake completes, and app data round-trips.

### Status
- 94 public theorems unchanged; all 24 deterministic suites green; parser fuzz clean. All three TLS
  1.3 suites negotiate and interop with OpenSSL. The verified core, not the interpreter, remains the
  single transcript and key-schedule authority.

## [0.71.0-dev] — Hash-parameterized key schedule + provider (toward AES-256-GCM-SHA384) — 2026-06-14

The second step toward `TLS_AES_256_GCM_SHA384`: the crypto *execution* layer now runs the key
schedule under whichever hash the negotiated suite carries (SHA-256 or SHA-384), exactly mirroring
the AES-GCM sequence where provider dispatch (0.67) and the seal path (0.68) preceded negotiation
(0.69). Behavior is unchanged for every suite negotiable today — they are all SHA-256 — but the
provider now demonstrably runs SHA-384 when handed a SHA-384 op.

### Key schedule (`Kroopt/Crypto/KeySchedule.lean`)
- Parameterized the whole RFC 8446 §7.1 schedule by `HashAlgorithm`. Added dispatch helpers
  `hashLen` (32/48), `hashOf` (SHA-256/384), `hkdfExtractH`, `hkdfExpandH`, and `hmacH`. Every entry
  point (`expandLabel`, `deriveSecret`, `emptyHash`, the early/handshake/master secret chain,
  `trafficIv`, `finishedKey`, …) takes the hash as a trailing argument **defaulting to SHA-256**, so
  the established SHA-256 callers compile and behave verbatim. `trafficKey` keeps its signature and
  derives the hash from the suite (`suite.hashAlg`), so it is already correct for AES-256.

### Provider (`Kroopt/Crypto/RealProvider.lean`)
- `submit` now binds and threads each op's `HashAlgorithm` instead of ignoring it: `.hkdfExtract`
  and `.hkdfExpandLabel` route through `hkdfExtractH`/`expandLabel` under the op's hash (and the
  absent-salt/IKM zero block is now `hashLen`-sized, so SHA-384's Early-Secret extract uses 48-byte
  zeros); `.installTrafficKeys` expands the IV under `suite.hashAlg`; `.computeServerFinished` and
  `.verifyFinished` compute the Finished MAC with `hmacH`/`finishedKey` under the op's hash.
- `Kroopt/Conn/Interpreter.lean`: `sealHandshakeRecord` threads `suite.hashAlg` into `trafficIv`, so
  the handshake record IV matches the key's hash.

### Tests
- `kroopt-realprovider-test` (+5, **34** total): drives `submit` with `.sha384` ops and cross-checks
  against the SHA-384 schedule — the Early Secret uses HKDF-Extract-384 (48 bytes), an Expand-Label
  uses HKDF-Expand-384, an `aes256GcmSha384` install derives a 32-byte key and 12-byte IV under
  SHA-384, and the SHA-384 result is shown to diverge from the SHA-256 computation of the same input.

### Trust posture
- No core/proof changes: 94 public theorems unchanged, all 24 suites green, parser fuzz clean. The
  SHA-256 path is behavior-identical (the only negotiable suites remain SHA-256).

### Remaining for AES-256-GCM-SHA384
1. Core `KeyScheduleDriver` must emit ops under `suite.hashAlg` (it currently hardcodes `.sha256`
   and length `32`) and the transcript hash must be set to the suite's hash on negotiation — the
   proof-touching core step.
2. Recognize `0x1302` in `suiteOfU16`, advertise the suite + SHA-384 in `realCapabilities`, and
   validate end-to-end (deterministic + OpenSSL `-ciphersuites TLS_AES_256_GCM_SHA384`).

## [0.70.0-dev] — SHA-384 HKDF/HMAC primitive layer (toward AES-256-GCM-SHA384) — 2026-06-14

The first step toward `TLS_AES_256_GCM_SHA384`, the one remaining suite whose key schedule differs
(SHA-384 changes the HKDF hash and the Finished/secret lengths from 32 to 48 bytes). This increment
lands and validates the SHA-384 HKDF/HMAC primitives; the hash-parameterized key schedule and the
negotiation come next, mirroring the AES-GCM sequence (0.66 primitives → 0.67/0.68 plumbing → 0.69
negotiation).

HACL ships HKDF for SHA-256 and SHA-512 but **not SHA-384** — though it does ship the
`HMAC-SHA384` primitive. Since HKDF is exactly the iterated-HMAC construction (RFC 5869) — the same
way HACL builds its own HKDF-256/512 internally — kroopt builds SHA-384 HKDF on the verified
HMAC-SHA384 primitive.

### This increment (TESTED)
- `Kroopt/Native/kroopt_ffi.c`: `kroopt_ffi_hmac384` (direct `Hacl_HMAC_compute_sha2_384`),
  `kroopt_ffi_hkdf_extract384` (HKDF-Extract = one HMAC), and `kroopt_ffi_hkdf_expand384`
  (RFC 5869 iterated HMAC, `T(i) = HMAC(PRK, T(i-1) || info || i)`, HashLen 48, fail-closed on
  `len > 255*48`). Same fail-closed length validation as the SHA-256 wrappers.
- `Kroopt/Crypto/Hacl.lean`: `hmac384`, `hkdfExtract384`, `hkdfExpand384` externs.

### Tests
- `kroopt-hacl-test` (+5 checks, **55** total): HMAC-SHA384 matches the published RFC 4231 TC1
  vector (anchoring the primitive); then the HKDF-384 construction is verified against that anchored
  primitive — Extract equals `HMAC(salt, IKM)`, Expand's first block equals `HMAC(PRK, info||0x01)`,
  Expand chains `T(2) = HMAC(PRK, T1||info||0x02)`, and the output length is honored. This checks the
  full iterated-HMAC logic against a vector-anchored HMAC.

### Trust posture
- HMAC-SHA384 is an ASSUMED HACL primitive (anchored to RFC 4231). The SHA-384 HKDF *construction*
  is kroopt's (HACL ships no SHA-384 HKDF) and is therefore TESTED rather than ASSUMED — verified to
  be the exact RFC 5869 iterated-HMAC construction over the anchored primitive. SHA-256 HKDF
  continues to use HACL's own HKDF directly. 94 public theorems unchanged.

### Remaining for AES-256-GCM-SHA384
1. Hash-parameterize `Kroopt/Crypto/KeySchedule.lean` (extract/expand/deriveSecret/finishedKey/
   emptyHash by `HashAlgorithm`) and thread the suite's hash through `RealProvider.submit` and the
   core transcript hash.
2. Recognize `0x1302` in `suiteOfU16`, advertise the suite + SHA-384 in `realCapabilities`, and
   validate end-to-end (deterministic + OpenSSL `-ciphersuites TLS_AES_256_GCM_SHA384`).

## [0.69.0-dev] — AES-128-GCM-SHA256 negotiated + served end-to-end (real OpenSSL interop) — 2026-06-14

The payoff of 0.66–0.68. `TLS_AES_128_GCM_SHA256` is now a fully negotiable, fully served suite: the
verified core selects it, the suite-aware seal path (0.68.0-dev) seals the flight with it, and an
independent TLS stack completes the handshake and an application-data round-trip. **OpenSSL 3.0.13
negotiates AES-128-GCM with kroopt and exchanges data on both the blocking and non-blocking server
drivers.** ChaCha20-Poly1305 is unchanged and remains fully servable; both are validated side by side.

### This increment
- `Kroopt/Parse/Handshake.lean`: `suiteOfU16` recognizes `0x1301` → `aes128GcmSha256`. Negotiation is
  client-preference among server-supported suites (first client-offered suite the server can serve).
  `0x1302` (AES-256-GCM-SHA384) is still withheld pending the SHA-384 schedule.
- `Kroopt/Crypto/Provider.lean`: `realCapabilities` advertises `TLS_AES_128_GCM_SHA256` alongside
  `TLS_CHACHA20_POLY1305_SHA256`. AES-256-GCM-SHA384 remains rejected at config validation.

### Tests / interop
- `kroopt-hardening-test` (+2 checks, **22**): negotiation-policy coverage — AES-128-only → AES-128;
  AES-128-before-ChaCha → AES-128; ChaCha-only → ChaCha; ChaCha-before-AES-128 → ChaCha.
- `kroopt-capabilities-test`: AES-128 now accepted at config validation; AES-256-GCM-SHA384 still
  rejected.
- `kroopt-correspondence-test` (33) and `kroopt-socketdriver-test` (6) migrated to AES-128: the
  production interpreter + real provider drive a full handshake to `connected` under AES-128 — over a
  real OS socket in the socket driver — with the post-`connected` app record and the close_notify all
  sealed and opened under AES-128. The shared `clientHelloMsg` fixture offers AES-128 first (like a
  browser), so the server now negotiates AES-128 from it; the client Finished verify_data is computed
  from the actual transcript (SHA-256 for both suites), so the migration was a key-length/primitive
  swap only.
- `scripts/tls-interop.sh`: `test_openssl` is parameterized by ciphersuite; the script now runs both
  `TLS_CHACHA20_POLY1305_SHA256` and `TLS_AES_128_GCM_SHA256` against OpenSSL on both drivers. All
  pass: OpenSSL reports `Cipher is TLS_AES_128_GCM_SHA256`, kroopt reaches `connected`, and app data
  round-trips in both directions.

### Trust posture
- No protocol proof affected; 94 public theorems unchanged. AES-128-GCM stays in the ASSUMED-verified
  crypto tier (Vale assembly); kroopt proves the protocol structure around it.

### Remaining
1. `TLS_AES_256_GCM_SHA384`: the SHA-384 key schedule + transcript (the one place SHA-384 changes the
   key-schedule/Finished lengths).
2. Broader interop (browsers — not testable in this environment).

## [0.68.0-dev] — Suite-aware handshake-flight seal path (last ChaCha hardcode removed) — 2026-06-14

Closes the gap 0.67.0-dev surfaced. The interpreter's `Conn.Interpreter.sealHandshakeRecord` — the
one remaining production path that hardcoded ChaCha20-Poly1305 for both key derivation and sealing —
now seals the server's encrypted handshake flight under the suite the keys were installed with. With
this, **every production seal/open path is suite-aware**: application records and all record opens
already routed through the suite-dispatched provider (0.67.0-dev); the handshake flight now does too.
The record/seal layer is no longer the blocker for AES-GCM negotiation.

Behavior is unchanged at this release — ChaCha20-Poly1305 is still the only negotiable suite, so the
installed suite is always ChaCha and the sealed bytes are identical to before. The change is the
plumbing that lets the flight follow the negotiated suite once negotiation is enabled.

### This increment (TESTED)
- `Kroopt/Crypto/Arena.lean`: the arena now tracks `installedSuites : List (Direction × Epoch ×
  CipherSuite)` with `recordInstalledSuite` / `lookupInstalledSuite`. The suite travels with the
  installed keys (single source of truth), so the interpreter never re-decides it. Reset on
  generation bump alongside the other per-connection install state.
- `Kroopt/Crypto/RealProvider.lean`: `.installTrafficKeys` records the suite as it installs the key/IV.
- `Kroopt/Conn/Record13.lean`: `sealRecord` / `sealRecord!` / `openRecord` take a `suite` parameter
  (defaulting to ChaCha20-Poly1305 so existing test callers are unchanged) and dispatch through
  `Real.aeadSealBySuite` / `aeadOpenBySuite`. The `ctLen := inner.size + 16` math is unchanged: the
  16-byte AEAD tag is uniform across all three TLS 1.3 suites, so the record-length/AAD reasoning
  holds for every suite.
- `Kroopt/Conn/Interpreter.lean`: `sealHandshakeRecord` looks up the installed (write, handshake)
  suite, derives the traffic key of the matching length, and dispatches the matching AEAD.

### Tests
- `kroopt-conn-test` (+2 checks, **15** total): `sealHandshakeRecord` seals a flight message under an
  installed AES-128-GCM suite and the record opens back to the plaintext; and the sealed bytes differ
  from the ChaCha sealing of the same secret — proving the flight seal follows the installed suite
  rather than a hardcoded one.

### Trust posture
- The arena lives in the impure Crypto zone (never imported by the verified core); the dependency gate
  confirms the pure zone is untouched. 94 public theorems unchanged.

### Remaining for AES-GCM negotiation (next increments)
1. Enable negotiation: recognize `0x1301` in `Parse.Handshake.suiteOfU16`, advertise
   `TLS_AES_128_GCM_SHA256` in `realCapabilities`, migrate the correspondence/socketdriver peer
   harness to AES-128 (the shared `clientHelloMsg` already offers AES-128 first). The seal path is
   now ready to serve it.
2. `TLS_AES_256_GCM_SHA384`: the SHA-384 key schedule + transcript.
3. Live `openssl -ciphersuites TLS_AES_128_GCM_SHA256` interop.


## [0.67.0-dev] — Suite-keyed AEAD provider dispatch (AES-128-GCM exercised end-to-end at the provider) — 2026-06-14

Builds on 0.66.0-dev (AES-GCM bound + KAT'd). The AEAD **provider** is now suite-aware: a record's
`RecordCryptoMeta.suite` selects AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 at seal/open. An
AES-128-GCM record now round-trips through the real provider path and is cross-checked byte-for-byte
against the KAT'd Vale primitive.

This increment deliberately stops short of **negotiating** AES suites, because the investigation
surfaced a real gap: the interpreter's record/handshake-seal path
(`Conn.Interpreter.sealHandshakeRecord`) still hardcodes ChaCha20-Poly1305 for both key derivation
and sealing. Until that path is suite-aware, the server could select AES-128 but would then seal its
handshake flight with ChaCha — so AES-GCM stays out of the negotiable/advertised set. Making the
seal path suite-aware is the next increment; negotiation + fixture migration follows it.

### This increment — provider AEAD dispatch (TESTED)
- `Kroopt/Crypto/Real.lean`: `aeadSealBySuite` / `aeadOpenBySuite` dispatch a `CipherSuite` to the
  matching HACL primitive (AES-128/256-GCM via the Vale path, ChaCha20-Poly1305 direct).
  `sealRecord` / `openRecord` now dispatch on `meta.suite` instead of hardcoding ChaCha. The FFI
  wrappers fail closed on a wrong-size key, so a suite/key mismatch can never emit ciphertext under
  the wrong primitive.
- `Kroopt/Crypto/RealProvider.lean`: the provider's `.aeadSeal` / `.aeadOpen` handlers dispatch on
  `meta.suite` through the same helpers.

### Tests
- `kroopt-realprovider-test` (+3 checks, **29** total): using the RFC 8448 §3 server handshake
  key/IV, an AES-128-GCM record seals + opens through the suite dispatch, the sealed bytes match a
  direct `Hacl.aes128GcmSeal` exactly (proving the record path routes to the real Vale AES, not
  ChaCha), and a tampered record is rejected (`verifyFailed`).

### Trust posture
- No protocol proof affected; 94 public theorems unchanged. The dispatch is a pure function over the
  ASSUMED-verified primitives.

### Still gating AES-GCM negotiation (next increments, in order)
1. Make the interpreter seal path (`sealHandshakeRecord`, app-record seal, `Conn.Record13.sealRecord`)
   suite-aware — thread the negotiated suite through so the server seals the suite it selected.
2. Enable negotiation: recognize `0x1301` in `Parse.Handshake.suiteOfU16`, advertise
   `TLS_AES_128_GCM_SHA256` in `realCapabilities`, and migrate the correspondence/socketdriver peer
   harness to AES-128 (the shared `clientHelloMsg` already offers AES-128 first, like a browser).
3. `TLS_AES_256_GCM_SHA384`: the SHA-384 key schedule + transcript.
4. Live `openssl -ciphersuites TLS_AES_128_GCM_SHA256` interop.


## [0.66.0-dev] — AES-GCM bound + KAT'd via HACL* Vale verified assembly — 2026-06-14

**Corrects a standing error.** Earlier releases (through 0.65.0-dev) described AES-128/256-GCM as
"environment-blocked." That was wrong. The block was a misdiagnosis on our side, not a gap in the
vendored HACL* tree: we searched for a *portable C* AES backend, didn't find one, and overlooked
the **Vale verified x86_64 assembly** (`aesgcm-x86_64-linux.S`) plus the EverCrypt dispatcher that
ship in the tree — the same production path NSS/Firefox use, and the verified one. This host has
AES-NI + PCLMULQDQ, so it runs. SHA-384 was never blocked either (long bound as `kroopt_ffi_sha384`).

This increment binds AES-GCM through the FFI and proves it against NIST vectors. It does **not** yet
negotiate the AES suites (that touches the verified core's suite enum + `selectSuite`, and the
SHA384 suite needs the key schedule under SHA-384) — those are the next increments.

### This increment — AES-GCM FFI binding (TESTED)
- Vendored `EverCrypt_AEAD.c`, `EverCrypt_AutoConfig2.c`, `aesgcm-x86_64-linux.S`, and
  `cpuid-x86_64-linux.S` into `Kroopt/Native/hacl/` (all dependent headers were already present).
- New `Kroopt/Native/kroopt_aesgcm.c`: `kroopt_ffi_aes128_gcm_seal/open` +
  `kroopt_ffi_aes256_gcm_seal/open`, with the exact fail-closed ABI of the ChaCha wrappers
  (seal → `ciphertext ++ tag(16)`, empty on malformed length; open → `[status] ++ plaintext`,
  status 1 + zeroed plaintext on auth/length failure). One-time `EverCrypt_AutoConfig2_init`.
- `lakefile.lean`: a second compile group in `extern_lib krooptCrypto` builds the AES sources with
  `-DHACL_CAN_COMPILE_VALE=1 -DHACL_CAN_COMPILE_VEC128 -DHACL_CAN_COMPILE_VEC256 -mavx2 -mavx -maes
  -mpclmul -msse4.2`. `HACL_CAN_COMPILE_VALE` gates *both* the CPUID detection in
  `AutoConfig2_init` and the `create_in` AES path — without it the whole path silently no-ops to
  "unsupported," which is how the original misdiagnosis happened. The portable-C primitives keep
  their original flags unchanged.
- `Kroopt/Crypto/Hacl.lean`: `aes128GcmSeal` / `aes128GcmOpen(Raw)` / `aes256GcmSeal` /
  `aes256GcmOpen(Raw)`, mirroring the ChaCha externs + `Option`-returning open wrappers.

### Tests
- `kroopt-hacl-test` (+9 checks, **50** total): AES-128-GCM and AES-256-GCM each — seal matches
  NIST GCM Test Case 4 (`ciphertext ++ tag`), seal/open round-trips, tampered ciphertext rejected
  (`none`), wrong-size key rejected fail-closed; plus the 128-bit output-size check. All driven
  through the Lean FFI against the live Vale assembly.

### Trust posture
- AES-GCM stays in the **ASSUMED-verified** crypto tier exactly like the other HACL*/EverCrypt
  primitives — the Vale assembly is verified upstream; kroopt's wrapper only marshals bytes and
  fails closed on malformed lengths. No protocol proof is affected; 94 public theorems unchanged.

### Still gating a non-dev v0.4.0
- AES suite **negotiation** (core `selectSuite` + suite enum; SHA-384 key schedule for the
  AES-256-GCM-SHA384 suite) and live `openssl -ciphersuites` interop — next increments.
- Browser interop (no browser in the environment), RFC 027 (stability) unstarted.


## [0.65.0-dev] — Consolidation: config-validation hardening + edge-feature checkpoint — 2026-06-14

A consolidation checkpoint for the constrained-profile edge feature band (0.53–0.64) plus a
config-validation hardening item. This is a logical breaking point — the negotiation and
configuration surface an HTTPS edge needs is feature-complete and live-validated — but the release
stays `-dev`: it is **not** a stability commitment (RFC 027 unstarted), and a true v0.4.0 still
requires the environment-blocked crypto breadth and browser interop below.

### This increment — ALPN identifier validation (TESTED)
- `validateEndpoint` now rejects malformed ALPN identifiers (RFC 7301 — each protocol name must be
  1..255 bytes), wiring in the previously-dead `ConfigError.invalidAlpn`. Empty and over-long
  (>255-byte) identifiers fail config validation. 2 new config checks; the validation proofs
  (`validateServerConfig_rejects_ambiguous`, `_preserves_generation`) are unaffected — they reason
  over `validateEndpoint`'s result opaquely — so all 94 theorems and the axiom profile hold.
- Config validation now covers: ambiguous/overlapping SNI routes (`ambiguousSni`, pre-existing),
  empty/no cipher suite (`noCipherSuite`), cert/key kind mismatch (`certKeyMismatch`), and malformed
  ALPN identifiers (`invalidAlpn`, new).

### Feature surface consolidated since the M37 band (0.48.0-dev)
All in the constrained TLS 1.3 server profile (X25519/P-256 ECDHE, ChaCha20-Poly1305, Ed25519 /
ECDSA-P256 / RSA-PSS server auth), each live-validated against OpenSSL/curl:
- P-256 ECDHE; ECDSA-P256 and RSA-PSS CertificateVerify (server-auth triad).
- SNI multi-certificate selection (exact and wildcard routes) and per-endpoint ALPN negotiation —
  both fixed from latent raw-extension-framing parser bugs and confirmed on the wire.
- Clean `handshake_failure` on no signature-scheme overlap (PROVEN; the one proof-touching item).
- Cert / private-key compatibility lint across all three key types (Ed25519, EC P-256, RSA), wired
  into the driver's startup (`CONFIG_LINT_OK`).
- HTTP/1.1 keep-alive over the kroopt+iotakt edge.

### Honest state for a non-dev / v0.4.0 release (NOT yet met)
- **Environment-blocked here:** AES-128/256-GCM and SHA-384 cannot be vendored (the available HACL*
  tree ships only the `EverCrypt_AEAD.c` dispatcher, no AES backend C); browser interop has no
  browser in this sandbox. Both gate a true v0.4.0 and need a HACL* source update / different host.
- **Deferred by their own RFC acceptance:** the real iotakt adapter (RFC 010), the async-crypto
  runtime ledger (RFC 031), the C zeroizing arena (RFC 037), API stability (RFC 027), and the
  release runbook (RFC 030).
- Trust posture unchanged: protocol PROVEN (94 theorems), crypto ASSUMED, wire TESTED + interop.
  Full sweep 394; hygiene/deps/axioms clean; fuzz 20000 clean.

## [0.64.0-dev] — RFC (v0.4): wildcard SNI — LIVE — 2026-06-14

The `ServerNamePattern.wildcard` route — implemented and proven since the SNI config model, but never
exercised over the wire — is now validated live. No core or proof change: this confirms the existing
`patternMatches` semantics (a single leftmost label followed by the suffix) against a real client.

- **Fixture + driver.** A new `wildcardServerConfig` routes `*.example.com` (one leftmost label) to
  the ECDSA-P256 leaf, with everything else falling to the default Ed25519 leaf; a `wildcard` driver
  profile serves it and lints both leaves at startup (`CONFIG_LINT_OK`).
- **Live-validated** against `openssl s_client -servername …`, each completing HTTP 200:
  `api.example.com` → ECDSA (wildcard matched the single leftmost label), while the bare
  `example.com` (no leftmost label), the multi-label `a.b.example.com` (wildcard matches exactly one
  label), and an unrelated `other.test` all correctly fall to the default Ed25519 leaf. This is the
  proven negative behavior — bare domain and multi-label prefix do **not** match — confirmed on the
  wire.
- **No core/proof surface touched.** The wildcard matching and its ambiguity rejection were already
  PROVEN/TESTED in the config suite; 94 theorems and the axiom profile are unchanged. Full sweep 392;
  hygiene/deps/axioms clean; fuzz 20000 clean.

## [0.63.0-dev] — RFC (v0.4): RSA leaf lint completes the cert/key check — TESTED + LIVE — 2026-06-14

Closes the one `CONFIG_LINT_SKIPPED` case from 0.62: the cert/private-key compatibility lint now
covers RSA leaves, so all three server-auth key types (Ed25519, EC P-256, RSA) are checked.

- **Minimal DER reader in `Kroopt.Crypto.CertLint`.** Unlike Ed25519/EC, an RSA SPKI wraps a
  `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` whose modulus length varies
  with key size, so a fixed-header anchor isn't enough. Added `readLen` (DER short + long-form length,
  up to four octets), `readInteger` (tag `0x02` + content), and `stripZeros` (normalizes the
  positive-integer `0x00` padding). `leafRsaPub` anchors on the rsaEncryption AlgId (OID
  1.2.840.113549.1.1.1 + NULL, RFC 8017), steps over the BIT STRING and `RSAPublicKey` SEQUENCE, and
  reads both INTEGERs; `rsaKeyMatches` compares the leading-zero–normalized `(modulus, exponent)` to
  the configured `(n, e)`. Still **TESTED, not PROVEN** — crypto trusted zone, no proof obligation;
  94-theorem axiom profile unchanged.
- **Validated on the real RSA fixture.** 3 checks in the real-provider suite: the RSA leaf's modulus
  and exponent match the configured 2048-bit key; a mismatched modulus is rejected; an RSA check
  against an Ed25519 certificate is rejected (no rsaEncryption SPKI). Real-provider suite 23 → 26;
  full sweep 392.
- **Driver.** The `rsa` profile now lints (was `CONFIG_LINT_SKIPPED`) and `multi` lints all three
  leaves; both report `CONFIG_LINT_OK` live against their real certificates. No profile reports
  SKIPPED anymore.
- **Trust posture unchanged.** Protocol PROVEN (94 theorems), crypto ASSUMED, cert/key lint TESTED +
  live across all three key types. Hygiene/deps/axioms clean; fuzz 20000 clean.

## [0.62.0-dev] — RFC (v0.4): cert / private-key compatibility lint — TESTED + LIVE — 2026-06-14

A config-load lint that catches a leaf certificate whose public key does not match the configured
private key — the classic "wrong key file" deployment slip that would otherwise surface only
mid-handshake as a CertificateVerify the peer rejects (RFC 011 §11.2, RFC 012). This is a config
**lint**, not peer-certificate path validation: no trust anchors, expiry, name, or revocation (those
remain in the deferred client/mTLS RFC).

- **New `Kroopt.Crypto.CertLint`.** Extracts the leaf SubjectPublicKeyInfo key directly from the DER
  by anchoring on the algorithm's fixed SPKI header — Ed25519 (RFC 8410 §10.1, the 32-byte raw key)
  and EC P-256 (RFC 5480, the 65-byte uncompressed point) — then compares it to the public key
  derived from the private key via HACL* (`ed25519Public` / `p256Public`). `ed25519KeyMatches` and
  `ecP256KeyMatches` return `false` on either a key mismatch or a wrong-algorithm certificate. The
  byte-scan (`findSub`) is fuel-bounded; the module lives in the crypto trusted zone and is **TESTED,
  not PROVEN** — it calls FFI derivation, so the verified core never depends on it and the 94-theorem
  axiom profile is unchanged.
- **Validated on real certificates.** 4 checks in the real-provider suite run against the
  openssl-generated fixture leaves: Ed25519 and EC P-256 leaves match their configured keys; a
  mismatched private key is rejected; an Ed25519 check against an EC certificate is rejected (no
  Ed25519 SPKI present). Real-provider suite 19 → 23; full sweep 389.
- **Wired into the driver.** `kroopt-iotakt` now lints the selected profile's cert/key pair at
  startup and logs `CONFIG_LINT_OK` / `CONFIG_LINT_MISMATCH` / `CONFIG_LINT_SKIPPED`. Live: `ed25519`,
  `ecdsa`, and `multi` (Ed25519 + EC P-256) all report OK against their real certs; `rsa` reports
  SKIPPED.
- **Deferred.** RSA leaves are not yet linted (variable-length INTEGER SPKI — a follow-up); the `rsa`
  profile reports SKIPPED rather than a false OK.
- **Trust posture unchanged.** Protocol PROVEN (94 theorems), crypto ASSUMED, this lint TESTED +
  live. Hygiene/deps/axioms clean; fuzz 20000 clean.

## [0.61.0-dev] — RFC (v0.4): no-overlap handshake_failure — PROVEN + LIVE — 2026-06-14

When a client's offered signature_algorithms don't intersect the schemes the selected certificate can
produce, the server now sends a clean `handshake_failure` instead of degrading to a total fallback
(which fails safe — the peer rejects a scheme it never offered — but is not the RFC-correct response).
This is the one deferred item that touches the **proven** `onClientHello` surface; it lands with the
axiom profile and all 94 public theorems intact.

- **Core (`onClientHello`).** The signature-scheme selection changed from a total `.getD`-fallback to
  a `match … | none => hsFail | some sigScheme => …` placed first in the budget-`ok` arm: with no
  overlap there is no scheme the server can both sign with and have the client accept, so it fails
  cleanly (RFC 8446 §9.2) rather than signing with an incompatible key.
- **Error/alert.** New `ProtocolError.unsupportedSignatureScheme` (analogous to `unsupportedGroup`),
  mapped to `handshake_failure` in `alertForProtocolError`; `Step`/`Uniform` match it under their
  existing `.protocol _` wildcards, and `alertForProtocolError_fatal_unless_close` stays total since
  `handshake_failure` is fatal.
- **Proofs (5, extended one split each).** `onClientHello_legal`, `hs_no_emit_onClientHello`,
  `hs_no_accept_generic_onClientHello`, `hs_no_aeadOpen_onClientHello` (Handshake) and
  `onClientHello_pp` (RecordPath) each gain one case for the new `hsFail` arm — handled identically to
  the existing budget-error `hsFail` arm. **94 theorems, axioms unchanged.**
- **Config placeholder.** A shared `ValidatedServerConfig.baseline` (a default endpoint advertising
  the baseline server-auth schemes) now backs the defaults of `State.initial` and `TlsConn.server`.
  The old total fallback had masked that core-level test states carried no endpoint at all; production
  always supplies its own validated config, so the placeholder is only ever negotiated against by
  direct-`step` tests. 2 new handshake unit checks (no-overlap → `handshake_failure`; matching scheme
  → no spurious failure).
- **Live-validated.** Ed25519-only server + `openssl -sigalgs ecdsa_secp256r1_sha256` → server-sent
  `handshake_failure` (`HANDSHAKE_FAILED` server-side, no peer certificate client-side); `-sigalgs
  ed25519` still completes (`Peer signature type: Ed25519`, HTTP 200).
- **Trust posture unchanged.** Protocol PROVEN (94 theorems), crypto ASSUMED, wire TESTED +
  interop-validated. Full sweep 385 checks; hygiene/deps/axioms clean; fuzz 20000 clean.

## [0.60.0-dev] — RFC (v0.4): ALPN negotiation — LIVE — 2026-06-14

ALPN protocol negotiation now works end-to-end — the same raw-framing bug class that `parseSni` fixed
for SNI in 0.59, now fixed for ALPN. Validated live against `openssl s_client -alpn …`: offering
`http/1.1` selects it (`ALPN protocol: http/1.1`), offering `h2,http/1.1` selects the one the endpoint
allows (`http/1.1`), and offering only `h2` negotiates no ALPN while the handshake still completes
(HTTP 200) — the "continue without ALPN" policy an edge server wants. ALPN composes with SNI: on the
multi-cert listener, `ecdsa.test` and `rsa.test` each select their certificate *and* negotiate
`http/1.1` from that endpoint's own allow-list.

- **Parser (core) — latent bug fixed.** `vch.alpn` stored the *raw* ALPN extension body as a single
  "protocol" (the `ProtocolNameList`/length framing), so it could never match a bare-name allow-list
  and ALPN never negotiated. A new bounded `parseAlpn` (RFC 7301: `list_len(2) ‖ (name_len(1) ‖ name)+`)
  extracts the offered protocol names in order; `parseAlpnAux` is structurally recursive on a fuel
  bound (the buffer size) over attacker-controlled input — no `partial`, pure-zone clean. The parser
  now stores `(findExt exts 16).map parseAlpn |>.getD []`. 3 new unit checks (one name, two names in
  order, too-short→empty). The proofs treat `vch.alpn` opaquely, so all 94 theorems and the axiom
  profile are unchanged.
- **Fixtures.** Every endpoint now advertises `http/1.1` (`allowedAlpn := [http11]`), so the
  per-endpoint allow-list drives negotiation — including each SNI route on the multi-cert config.
- **Trust posture unchanged.** Protocol PROVEN (94 theorems), crypto ASSUMED, wire TESTED +
  interop-validated. Full sweep 383 checks; hygiene/deps/axioms clean; fuzz 20000 clean.

With SNI (0.59) and ALPN (0.60) both parsed correctly, the server now does correct per-hostname
certificate selection and protocol negotiation — the extension handling an HTTPS edge needs.

## [0.59.0-dev] — RFC (v0.4): SNI multi-certificate selection — LIVE — 2026-06-14

One kroopt server now presents a **different certificate and signature scheme per SNI hostname**
(RFC 6066 server_name → RFC 8446 §4.4.2.2 cert-aware signing). Validated live: `ecdsa.test` →
ECDSA-P256 leaf + `ecdsa_secp256r1_sha256`, `rsa.test` → RSA-2048 leaf + `rsa_pss_rsae_sha256`, any
other name (or no SNI) → the default Ed25519 leaf — each completing the TLS 1.3 handshake and HTTP
200 against `openssl s_client -servername …`. This composes the SNI routing, the three server-auth
schemes, and the cert-aware negotiation built across v0.4 into one listener.

- **Parser (core) — latent bug fixed.** `vch.sni` was the *raw* `server_name` extension body (the
  `ServerNameList`/`name_type`/length framing), so it could never match a bare-hostname route and SNI
  routing always fell through to the default. A new bounded `parseSni` (RFC 6066:
  `list_len(2) ‖ name_type(1=0x00) ‖ host_len(2) ‖ host`) extracts the bare hostname; the parser now
  stores `(findExt exts 0).bind parseSni`. Bounds-checked against the extension length; 3 new unit
  checks (extract, truncated-reject, non-host_name-reject). The proofs treat `vch.sni` opaquely, so
  all 94 theorems and the axiom profile are unchanged.
- **Provider — multi-key dispatch.** `RealCryptoConfig` gains `ecdsaPriv` (the ECDSA-P256 scalar),
  kept separate from `certPrivate` (the Ed25519 seed) and `rsaN/rsaE/rsaD`, so one config holds an
  Ed25519 *and* an ECDSA *and* an RSA key at once and `signCertificateVerify` selects by the
  negotiated scheme. The single-cert ECDSA fixtures move their scalar to `ecdsaPriv` accordingly.
- **Fixtures.** `multiCfg` (all three keys) and `multiCertServerConfig` (default Ed25519 endpoint +
  exact SNI routes `ecdsa.test`/`rsa.test`); the kroopt-iotakt driver gains a `cert=multi` profile.
- **Trust posture unchanged.** Protocol PROVEN (94 theorems), crypto ASSUMED (vendored HACL*), wire
  TESTED + interop-validated. Full sweep 380 checks; hygiene/deps/axioms clean; fuzz 20000 clean.

Known limitation: SNI matching is exact + single-label wildcard on the parsed hostname; the ALPN
extension has the same raw-framing shape `parseSni` just fixed for SNI and is a parallel follow-up.

## [0.58.0-dev] — RFC (v0.4 operational polish): HTTP/1.1 keep-alive — multi-request connections — 2026-06-14

Removes the one-request-per-handshake limitation: a single TLS connection now serves **many HTTP
requests** (HTTP/1.1 keep-alive), so real clients stop paying a full handshake per request. This is an
**integration-layer** change — the kroopt **core is unchanged** (94 theorems, axiom profile untouched):
its application-data send/recv path already handled multiple records, and this increment exercises that
proven path — including the read/write sequence-number monotonicity the core proves — live under
sustained traffic. The serving logic lives in the kroopt-iotakt driver.

- **kroopt-iotakt driver.** `tryServe` now responds and leaves the connection in `connected` rather
  than closing; the response carries `Connection: keep-alive`. Subsequent requests arrive as further
  readable events and are served the same way. The connection closes when the client sends
  `close_notify`/EOF (the existing terminal path closes and counts it) or when a per-connection bound
  `maxKeepAlive = 100` is reached (graceful `close_notify`). A `served` counter on `ConnState` enforces
  the bound — bounded everything, RFC 019 ethos.
- **Live validation.** curl issuing several URLs to the same host completes them over **one TCP/TLS
  connection** (`num_connects = 1`, then `0`), and the driver logs N `HTTP_REQ`/`HTTP_RESP` pairs on a
  single fd followed by one `CONN_CLOSED (served N request(s))`. Verified across all three cert
  profiles (Ed25519, ECDSA-P256, RSA-PSS): 4 requests per connection, every response HTTP 200.
- **kroopt core.** No change; all gates green (94 theorems, deps/hygiene clean).

Known limitation: request framing is per-record (sequential, non-pipelined clients), which covers
curl/browser keep-alive; HTTP pipelining and a request split across records are future refinements.

## [0.57.0-dev] — RFC (v0.4 breadth): RSA-PSS LIVE — server-auth triad complete — 2026-06-14

Turns RSA-PSS on for live handshakes, completing the TLS 1.3 server-auth triad: **Ed25519, ECDSA-P256,
and RSA-PSS are all negotiated cert-aware and interop-validated** against OpenSSL and curl. Additive —
94 theorems and the axiom profile unchanged; the cert-aware selection from 0.55.0-dev did the heavy
lifting, so this step was a parser code point + config + driver wiring.

- **Parser.** `sigSchemeOfU16` recognizes `rsa_pss_rsae_sha256` (0x0804) alongside Ed25519 and
  ECDSA-P256. A ClientHello offering only a non-presentable scheme (e.g. rsa_pss_pss_sha256) is still
  rejected.
- **RSA endpoint + driver.** `rsaServerConfig` advertises `rsaPssRsaeSha256` over the RSA-2048 leaf;
  the kroopt-iotakt driver's `cert` profile is now three-way (`ed25519` | `ecdsa` | `rsa`), drawing a
  fresh per-connection nonce/salt for the ECDSA nonce or PSS salt as appropriate.
- **Live validation (all three, one server each):**
  - Ed25519 → `Peer signature type: Ed25519`, HTTP 200
  - ECDSA-P256 (`-sigalgs ecdsa_secp256r1_sha256`) → `Peer signature type: ECDSA`, HTTP 200
  - RSA-PSS (`-sigalgs rsa_pss_rsae_sha256`) → `Peer signature type: RSA-PSS`, `Peer signing digest:
    SHA256`, HTTP 200; curl over the RSA server → HTTP 200.
- **Tests.** Hardening updated for the widened capability (RSA-PSS now presentable; rsa_pss_pss_sha256
  is the unpresentable case). All 24 suites green (377 checks); fuzz clean; all gates green.

Crypto remains ASSUMED (vendored HACL\*), protocol PROVEN (94 theorems), wire TESTED + interop-validated
across all three server-auth schemes. The key-exchange dimension spans x25519 + secp256r1; server-auth
spans Ed25519 + ECDSA-P256 + RSA-PSS — all live.

## [0.56.0-dev] — RFC (v0.4 breadth): RSA-PSS/SHA-256 server-auth signing — crypto + provider path — 2026-06-14

Third v0.4 server-auth scheme: kroopt can now **produce RSA-PSS (rsa_pss_rsae_sha256) CertificateVerify
signatures** (RFC 8446 §4.2.3), completing the server-auth triad (Ed25519 + ECDSA-P256 + RSA-PSS) and
unlocking real-world RSA certificates. This increment lands the crypto primitive and provider signing
path — all additive, with no change to the proven surface (94 theorems, axiom profile unchanged). A
parser code point for 0x0804 plus an RSA server config and a live interop are the explicit next step
(the cert-aware negotiation built in 0.55.0-dev already selects per endpoint, so that step is light).

- **Vendored crypto (assumed, not hand-rolled).** Added `Hacl_RSAPSS.c` + `Hacl_Bignum.c` (generic
  bignum) to the vendored HACL tree and the lakefile; both compile against the existing internal
  headers. Two FFI entry points (`kroopt_ffi_rsapss_sign`, `_verify`) load the key via
  `Hacl_RSAPSS_new_rsapss_load_skey`/`_pkey`, sign/verify with SHA-256, and free the key. Sign fails
  closed on empty key material; bit lengths are byte-aligned.
- **Bindings.** `Hacl.rsapssSign (n e d salt msg)` returns the raw RSA signature (`n.size` bytes, no
  DER wrapper — unlike ECDSA); `Hacl.rsapssVerify (n e) saltLen sgnt msg`. TLS 1.3 uses
  saltLen = hashLen = 32.
- **KAT (`Tests/Hacl.lean`, now 41 checks).** A generated RSA-2048 keypair drives a sign→verify
  round-trip (the standard known-answer for randomized PSS), tamper-rejection, signature sizing, and a
  fail-closed empty-key check.
- **Provider signing path.** `RealProvider.submit` handles `signCertificateVerify .rsaPssRsaeSha256`
  via `rsapssSign`, returning the raw signature; `RealCryptoConfig` gains defaulted `rsaN`/`rsaE`/`rsaD`
  and reuses the per-connection `signNonce` as the 32-byte PSS salt (fresh per connection). The match
  over signature schemes is now exhaustive (the wildcard is gone). The realprovider suite (19 checks)
  confirms the dispatch produces a signature that verifies against the public key.
- **Fixtures.** An RSA-2048 leaf (`rsaCertDer`, modulus = `rsaN`) and `rsaCfg` are in place for the
  upcoming interop.
- **Validation.** All 24 suites green (376 checks); parser fuzz clean; all gates green.

Crypto remains ASSUMED (vendored HACL\*), protocol PROVEN, wire TESTED. Server-auth signing now spans
Ed25519 + ECDSA-P256 (both live) + RSA-PSS (signing path in place, pending parser code point + interop).

## [0.55.0-dev] — RFC (v0.4 breadth): cert-aware signature-scheme negotiation — ECDSA-P256 LIVE — 2026-06-14

Turns ECDSA-P256 on for live handshakes by making the core present a signature scheme the *selected
certificate* can produce. An ECDSA-cert server now negotiates `ecdsa_secp256r1_sha256` and is
interop-validated against OpenSSL and curl; the Ed25519 path is unchanged. The 94 protocol theorems
and the axiom profile are untouched — the selection is *total*, so `onClientHello`'s control flow (and
thus every edge/discipline lemma over it) is identical to before.

- **Cert-aware selection (core).** `onClientHello` now chooses the presented scheme as the first of
  the selected endpoint's `signatureSchemes` that the client offered, preferring the server's order
  (RFC 8446 §4.2.3 / §4.4.2.2). With no overlap it falls back to the certificate's primary scheme,
  which the peer then rejects (fail-safe) rather than the server ever signing with an incompatible key.
  A clean server-side `handshake_failure` on no-overlap is a noted future refinement (it would add a
  branch to the proven negotiation surface and so warrants its own proof-careful change).
- **`ValidClientHello` now carries `offeredSigSchemes`** (the recognized offered schemes, client
  order, non-empty) instead of a single parser-chosen scheme — the cert-dependent choice belongs in
  the core, not the config-free parser.
- **Parser.** `sigSchemeOfU16` recognizes Ed25519 (0x0807) **and** ECDSA-P256 (0x0403);
  `recognizedSigSchemes` returns the offered overlap; `parseClientHello` rejects a ClientHello that
  offers no presentable scheme (e.g. RSA-PSS only).
- **ECDSA endpoint + driver.** A self-signed ECDSA-P256 leaf fixture (`ecdsaServerConfig`,
  `ecdsaCertDer`/`ecdsaCertPriv`, keypair-verified) advertises `ecdsaSecp256r1Sha256`. The
  kroopt-iotakt driver gains a `cert` profile (`… [mode] [ed25519|ecdsa]`): on each connection it draws
  a fresh 32-byte ECDSA signing nonce from OS entropy (never reused — one signature per handshake) and
  selects the ECDSA config + server config.
- **Live validation.** ECDSA server vs OpenSSL `s_client -sigalgs ecdsa_secp256r1_sha256` →
  `Peer signature type: ECDSA`, `Peer signing digest: SHA256`, HTTP 200; vs curl (TLS 1.3) → HTTP 200
  with the correct body. Ed25519 server → `Peer signature type: Ed25519`, HTTP 200 (regression-clean).
- **Tests.** Hardening/Wire updated for the widened capability (ECDSA-P256 now presentable; RSA-PSS-only
  is the unpresentable case). All 24 suites green (371 checks); fuzz clean; all gates green.

Server-auth now spans Ed25519 + ECDSA-P256, both negotiated and live. Crypto remains ASSUMED (vendored
HACL\*), protocol PROVEN (94 theorems), wire TESTED + interop-validated.

## [0.54.0-dev] — RFC (v0.4 breadth): ECDSA-P256 server-auth signing — crypto + provider path — 2026-06-14

Second v0.4 algorithm-breadth step: kroopt can now **produce ECDSA-P256 / SHA-256 CertificateVerify
signatures** (RFC 8446 ecdsa_secp256r1_sha256), the second required server-auth scheme alongside
Ed25519. This increment lands the crypto primitive, wire encoding, and provider signing path — all
additive, with no change to the proven negotiation surface (94 theorems, axiom profile unchanged). The
cert-aware *negotiation selection* and a live ECDSA-certificate interop are the explicit next step (they
touch the proven `onClientHello` edge/discipline lemmas and so warrant a focused, proof-careful turn).

- **Vendored crypto (assumed, not hand-rolled).** Reuses the `Hacl_P256.c` curve C vendored for P-256
  ECDHE. Two FFI entry points (`kroopt_ffi_ecdsa_p256_sign`, `_verify`) bridge to
  `Hacl_P256_ecdsa_sign_p256_sha2`/`_verif_p256_sha2`; sign hashes the input with SHA-256 internally
  and takes an explicit per-signature nonce `k`. Both fail closed on wrong-size key/nonce (RFC 037 §2).
- **DER wire encoding.** `Hacl.derEncodeEcdsaSig` encodes the raw `r‖s` as ASN.1
  `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 8446 §4.4.3, RFC 3279 §2.2.3) with
  minimal, positive INTEGER encoding; `ecdsaP256SignDer` chains sign + encode.
- **KAT (`Tests/Hacl.lean`, now 37 checks).** A NIST CAVP 186-4 ECDSA SigGen P-256/SHA-256 vector with a
  fixed nonce (known-answer `r‖s`), verify accept/reject, DER well-formedness, and a fail-closed nonce
  check.
- **Provider signing path.** `RealProvider.submit` handles `signCertificateVerify .ecdsaSecp256r1Sha256`
  via `ecdsaP256SignDer`, returning the DER signature; `RealCryptoConfig` gains a defaulted `signNonce`
  (drawn fresh per connection at the IO layer when the cert key is ECDSA — never reused, as the server
  signs CertificateVerify once per handshake). The fake provider is already scheme-agnostic. The
  realprovider suite (18 checks) confirms the dispatch produces a well-formed DER Ecdsa-Sig-Value.
- **Validation.** All 24 suites green (370 checks); parser fuzz clean; all gates green.

Crypto remains ASSUMED (vendored HACL\*), protocol PROVEN, wire TESTED. The key-exchange dimension now
spans x25519 + secp256r1 (0.53.0-dev); the server-auth dimension has the ECDSA-P256 *signing machinery*
in place behind Ed25519, pending the negotiation/cert wiring to select and present it on a live
connection.

## [0.53.0-dev] — RFC (v0.4 breadth): secp256r1 (P-256) ECDHE as a second key-exchange group — 2026-06-14

First algorithm-breadth increment of the v0.4 line: kroopt now negotiates **P-256 (secp256r1) ECDHE**
in addition to x25519, validated end-to-end against OpenSSL over the live iotakt loop. The change is
purely additive — the structural proofs are group-agnostic (no proof references any `NamedGroup`), so all
94 theorems and their axiom profile are unchanged.

- **Vendored crypto (assumed, not hand-rolled).** `Hacl_P256.c` + `Hacl_Bignum256.c` from the HACL\*
  distribution are vendored into `Kroopt/Native/hacl/` and registered in the `krooptCrypto` extern lib.
  Two FFI entry points (`kroopt_ffi_p256_public`, `kroopt_ffi_p256_shared`) bridge to
  `Hacl_P256_ecp256dh_i`/`_r`; the wire `key_share` is the uncompressed point `0x04‖X‖Y` (65 bytes) and
  the shared secret is the X-coordinate (32 bytes, RFC 8446 §7.4.2). Both fail closed on wrong-size or
  malformed input (RFC 037 §2).
- **KAT (`Tests/Hacl.lean`, now 32 checks).** A NIST CAVP ECC-CDH P-256 vector for standards
  conformance, plus DH symmetry (d·(e·G) == e·(d·G)) self-consistency and three fail-closed checks.
- **Core wiring.** `CryptoOp.ecdheP256` joins `ecdheX25519`; `onServerRandomDone` emits the op matching
  the negotiated group. The ClientHello parser's `findKeyShare` (replacing `findX25519Share`) selects the
  best offered group — x25519 preferred, else secp256r1 — and validates the chosen point's wire length
  before negotiation. The ServerHello already echoes `namedGroupToU16 selectedGroup` (→ 0x0017).
- **Provider wiring.** The real and fake `CryptoProvider`s handle `ecdheP256`; the real one uses
  `Hacl.p256Public`/`p256Shared` over the ephemeral scalar already drawn at the IO layer.
- **Hardening (incidental).** Key-share wire lengths are now validated at parse time (x25519 = 32 bytes,
  secp256r1 = 65-byte uncompressed point); the four fake-handshake fixtures were updated to present
  well-formed 32-byte x25519 shares.
- **Validation.** All 24 suites green (364 checks); parser fuzz clean at 40 000 iterations; all gates
  green. Live interop over the real iotakt `EventLoop`: `openssl s_client -groups P-256` →
  `Server Temp Key: ECDH, prime256v1` + HANDSHAKE_OK; `curl --curves P-256` → HTTP/1.1 200 with the
  correct body and graceful close. x25519 regression-clean (`Server Temp Key: X25519`, HANDSHAKE_OK).

Crypto remains ASSUMED (vendored HACL\*), protocol PROVEN, wire TESTED + interop-validated. The cipher
suite (TLS_CHACHA20_POLY1305_SHA256) and server-auth signature (Ed25519) are unchanged; this increment
widens the key-exchange dimension only.

## [0.52.0-dev] — RFC 015/013: HTTPS termination end-to-end (curl + Python) + graceful close_notify — 2026-06-13

The v0.3 vision realised end to end: a Lean edge server **terminates TLS 1.3 itself and answers an HTTP
request**, validated by two independent HTTP clients, with a clean TLS shutdown.

- `Tests/LiveServerNb.lean` gains an `http` mode (`kroopt-live-server-nb <sock> http`): after the
  handshake it receives the client's HTTP request over the TLS channel, serves a fixed HTTP/1.1 `200 OK`
  page, then closes gracefully. The fixed handler stands in for jemmet, which owns HTTP semantics in
  production (RFC 015) — kroopt's job is the verified plaintext channel, and this proves that channel
  carries real HTTP that an off-the-shelf HTTP client accepts.
- **Graceful close (RFC 8446 §6.1 / RFC 013).** The server drives `InputEvent.appClose .graceful`, which
  the core turns into a sealed, encrypted `close_notify` (alert level warning, description close_notify)
  under the application write epoch — the same AEAD-seal path as application data — then closes the
  transport. This removes the cosmetic post-close `unexpected eof` clients logged before.
- `scripts/https-e2e.sh` drives two independent clients:
  - **curl 8.5 (OpenSSL)** over the unix socket — receives `HTTP/1.1 200 OK` and the HTML body, exit 0;
  - **Python `ssl` + a raw HTTP GET** — receives `200 OK` with the body **and asserts the close is
    graceful**: `recv` returns a clean empty read (`PY_CLEAN_CLOSE True`) rather than raising a TLS
    truncation error, confirming the `close_notify` is well-formed and authenticated.
  All four checks pass, stable across repeated runs.

This runs over the non-blocking readiness reactor (0.51.0-dev), so the full path exercised is:
real socket → non-blocking `Transport` → verified core (handshake, records, app data, close) →
HTTP handler → real HTTP client. The verified core and the four repo gates are unchanged (handler +
close-drive + script only): full build, all 4 gates (36 pure-zone files, 94 theorems), all 24 suites,
parser fuzz (40000), the HACL\*↔OpenSSL and Record13↔Python crypto-interop scripts, the ASan/UBSan
sanitizer harness, the raw TLS interop (both drivers, both clients), and the HTTPS e2e all stay green.

Honest scope: the HTTP handler is a fixed stand-in, not jemmet itself (jemmet is a sibling project, not
vendored here) — the genuine jemmet integration remains RFC 015's target. The transport is still the
test socket glue / `SocketReactor` stand-in, not the real iotakt adapter (the deferred binding). What is
now demonstrated: kroopt terminates a real TLS 1.3 connection from an independent client and serves it
real HTTP over the verified channel, opening and closing cleanly.

## [0.51.0-dev] — RFC 010 §6: non-blocking readiness-driven reactor (production I/O shape) — 2026-06-13

The live server now also runs over a **non-blocking, readiness-driven reactor** — the production I/O
shape RFC 010 §6 specifies and the form a real `iotakt` adapter takes (Requirements §2.3, §21 v0.3) —
in addition to the blocking driver from 0.49/0.50. Both complete the full handshake **and** an
application-data round-trip with OpenSSL `s_client` and Python `ssl`.

- `Tests/LiveServerNb.lean` (`kroopt-live-server-nb`) drives the verified core + production interpreter
  through a real, IO-backed `Transport` instance, `SocketReactor`. The interpreter is already generic
  over the `Transport` typeclass; the reactor is simply another instance — no core or interpreter change.
  A `poll`/non-blocking-`recv`/non-blocking-`send` loop fills the reactor's inbound buffer and drains its
  outbound buffer in IO, while the *pure* interpreter pulls bytes via `Transport.recv` (turning the
  core's `readTransport` actions into `transportBytes`) and pushes its flight via `Transport.send`.
- Honors the non-blocking contract: readiness is a hint (a `recv` may still report `wouldBlock`), partial
  writes are retried on the next writable poll (`flushOutbound`), and `transportEof` is surfaced on a
  clean close. Because a non-blocking `recv` returns chunks that can bundle several records (unlike a
  one-record blocking read), `drainBuffered` re-drives the core with empty `transportBytes` to consume
  every complete record the chunk delivered, stopping at a partial record — so a client whose Finished
  and first application record arrive in one chunk is handled correctly.
- New test-only FFI in `Kroopt/Native/kroopt_socket.c`: `kroopt_sock_set_nonblocking` (O_NONBLOCK),
  `kroopt_sock_recv_nb` (status-prefixed: data / wouldBlock / eof / error), `kroopt_sock_send_nb`
  (partial-accept / wouldBlock / error), and `kroopt_sock_poll` (readable/writable bitmask).
- `scripts/tls-interop.sh` now exercises **both** drivers against **both** clients — 8 checks:
  {OpenSSL, Python} × {blocking, reactor} × {handshake, app-data} — all green and stable across repeated
  runs despite non-deterministic TCP segmentation.

The verified core and the four repo gates are untouched (this is interop-harness + transport-adapter
work): the full build, all 4 gates (36 pure-zone files, 94 theorems), all 24 suites, parser fuzz
(40000), the HACL\*↔OpenSSL and Record13↔Python crypto-interop scripts, and the ASan/UBSan sanitizer
harness all stay green.

Next in the arc: graceful `close_notify` on the live path (clients currently log a cosmetic post-close
eof), then the `iotakt`-backed `Transport` instance proper (when iotakt is vendored — `SocketReactor` is
the production-shaped stand-in today), and jemmet HTTPS E2E (RFC 015), the v0.3 acceptance target.

## [0.50.0-dev] — RFC 026/004: live application-data round-trip with OpenSSL + Python — 2026-06-13

Building on the 0.49.0-dev handshake interop, the live server now exercises the **post-handshake
application-data path** with the same two independent clients — not just the handshake. After reaching
`connected`, `Tests/LiveServer.lean` reads one application-data record from the client, decrypts it under
the client application-traffic key, and seals a fixed response under the server application-traffic key
and writes it back:

- The exchange threads the live `RuntimeState` (carrying the `SecretArena` with the derived
  application-traffic keys) out of `driveToConnected`, so the post-handshake seal/open use the real
  installed keys. Delivery of received plaintext is **demand-driven**, exactly as the core models it
  (RFC 004 §9): receiving the record decrypts and buffers it (no handler emits `emitPlaintext`), and the
  buffered plaintext is delivered only when the application requests a read — so the driver feeds
  `transportBytes` then `appRecvRequested`, and the response goes out via an explicit `appSend`.
- `scripts/tls-interop.sh` now drives a full request/response: OpenSSL `s_client` and Python `ssl` each
  send a line of application data after the handshake and read the server's reply. Both observe kroopt's
  sealed response (`kroopt: hello over TLS 1.3`) and the server confirms it decrypted each client's record
  (`APP_RECV … decrypted from client`) and sealed its own (`APP_SENT …`). This validates the application
  record path — server-side seal *and* open under TLS 1.3 traffic keys — against two independent stacks,
  closing the handshake-only gap noted at 0.49.0-dev.

The verified core and the four repo gates are untouched (this is interop-harness work): the full build,
all 4 gates (36 pure-zone files, 94 theorems), all 24 suites, parser fuzz (40000), the HACL\*↔OpenSSL and
Record13↔Python crypto-interop scripts, and the ASan/UBSan sanitizer harness all stay green, alongside the
live `kroopt server ↔ OpenSSL + Python` handshake **and** app-data interop.

Next in the arc: an `iotakt`-driven production network path (the socket helpers remain test-only glue),
readiness-driven non-blocking progress (`O_NONBLOCK` + partial read/write), and jemmet HTTPS E2E
(RFC 015) — the v0.3 acceptance target.

## [0.49.0-dev] — RFC 010/012/026: live TLS 1.3 interop (OpenSSL + Python) over a real socket — 2026-06-13

### RFC 010 (ACTIVE) — the verified core drives a handshake over a real OS socket

The real-socket arc toward v0.3 begins: RFC 010 is unfrozen now that the M37 native-hardening band has
landed. Where `Tests.SocketHandshake` showed the record layer survives real kernel I/O, this drives the
actual `Kroopt.Core.step` machine + production interpreter over a real socket.

- `Tests/SocketDriver.lean` (`kroopt-socketdriver-test`, 6 checks): an AF_UNIX socketpair carries a real
  ClientHello from the wire into the verified core (with the real HACL\* provider and the deterministic
  RFC 8448-backed fixtures), and the sealed server flight the core produces is written back to the wire.
  The peer reads the flight off the socket and confirms it opens with a cleartext ServerHello record and
  that every subsequent record is an encrypted record (outer `application_data` 0x17); the core reaches
  `sentServerFinished` over real I/O. A second socketpair completes the **full round-trip to `connected`**:
  the peer puts a valid client Finished on the wire (sealed under the client handshake-traffic key the
  server derived, over the through-server-Finished transcript — what a real client computes itself), the
  core opens it, `verifyFinished` checks the MAC, and the handshake reaches `connected` over real kernel I/O.
- The interpreter stays pure: all syscalls live in a thin `driveOverSocket` loop (read wire bytes → advance
  the core → flush only the bytes the core authorised), the shape RFC 010 §6 specifies — the core decides
  what is legal to write, the driver only moves it. A no-op staging `Transport` keeps authorised output in
  `RuntimeState.outbound` for the driver to flush. The socket helpers remain test-only glue; production
  reaches the network through iotakt.

### RFC 012 — the server presents its configured certificate (live-interop prerequisite)

Until now the server sent (and committed to its transcript) an *empty* Certificate: self-consistent in
the model, but a real client both rejects an empty `certificate_list` and computes its transcript over a
real one, so no external client could ever complete the handshake. The configured public certificate DER
now flows end to end, transcript-consistently:

- The public chain DER is carried on `EndpointConfig.der` and resolved once during negotiation into
  `NegotiationState.selectedCertDer`. It is *public* — the private key stays behind its secret handle, so
  no secret bytes enter a Lean value, and neither `CertificateChainHandle` nor any `Repr`/`DecidableEq`
  derivation is disturbed (the DER lives only on `Inhabited`-only structures).
- A single serializer, `Kroopt.Core.serializeServerCertificate`, produces the Certificate bytes for *both*
  the core's transcript contribution and the bytes the interpreter writes to the wire (the
  `writeCertificate` action now carries the DER, not an opaque handle). The two agree by construction
  (RFC 031 single transcript authority, RFC 032 single serializer). With no chain configured the DER is
  empty and it emits the prior empty `certificate_list`, so every in-model test and proof is unchanged —
  the full build, all 24 suites, fuzz, both interop scripts, and the sanitizer stay green.
- `Tests/SocketDriver.lean` now drives the handshake with a real config (`Tests.RealFixtures.realServerConfig`,
  the fixture Ed25519 leaf cert): the flight carries a real non-empty Certificate, that DER is confirmed in
  the core's committed transcript, and the handshake still reaches `connected` over the real-cert transcript.

### RFC 026 (de-risk) — kroopt's core parses a *real* client's ClientHello

Before building the listening-socket orchestration for live interop, the biggest unknown was whether the
verified core handles a real, non-fixture ClientHello (the in-model fixture is hand-built; a real client's
is larger, with its own extension set, random, and key_share). That risk is now retired:

- `scripts/real-ch-interop.sh` generates a genuine TLS 1.3 ClientHello with Python's `ssl` module (a real
  independent implementation, on OpenSSL 3.0) via a memory BIO — no server needed — and feeds it to the
  core (`Tests/RealChParse.lean`, exe `kroopt-realch-interop`) with the real HACL\* provider. The core
  parses it, negotiates `TLS_CHACHA20_POLY1305_SHA256` / x25519, performs the ECDHE against the client's
  real key_share, and produces a 661-byte server flight — reaching `sentServerFinished`. The ClientHello is
  freshly random each run, so this also fuzzes the happy path against a real client's wire format.
- The exe is `-interop`, not `-test`, so it stays out of the standalone suite sweep (it needs the script to
  generate the ClientHello first); it joins `ed25519-interop.sh` / `record-interop.sh` as a script-driven
  interop guard.

This confirms the path to live interop is now orchestration, not parser work: a real listening socket
(`listen`/`accept` FFI), handling the client's `change_cipher_spec` + real client Finished across multiple
round-trips, and confirming an independent client *accepts* the flight (the one thing the in-model client,
which does not verify CertificateVerify, cannot prove). That full round-trip is the next increment.

### RFC 8446 §4.1.3 — ServerHello echoes the client's legacy_session_id

A real client (OpenSSL in middlebox-compatibility mode) sends a 32-byte `legacy_session_id` and rejects
any ServerHello whose `legacy_session_id_echo` does not match it byte-for-byte. The server now captures
the client's session_id in the ClientHello parser, carries it as `ValidClientHello.sessionId` →
`NegotiationState.clientSessionId`, and echoes it in the typed ServerHello action — so the core's
transcript contribution and the bytes on the wire stay identical (RFC 031/032). A minimal client sends
an empty session_id, so every in-model handshake, its transcript, and the proofs over it are byte-for-byte
unchanged.

### RFC 026 — live TLS 1.3 interop with independent clients (the v0.3 prize)

kroopt's verified core + production interpreter now complete a full TLS 1.3 handshake against real,
independent TLS implementations:

- `Tests/LiveServer.lean` (`kroopt-live-server`) runs the core as a server on an AF_UNIX listening socket
  (new `kroopt_sock_listen` / `kroopt_sock_accept` test glue). Real OS entropy is drawn at the IO layer
  (RFC 034 §4 — the pure provider never draws entropy): the ephemeral X25519 key and the ServerHello
  random come from `Hacl.randomBytes` and are injected, the ephemeral into the provider config and the
  random as the single `randomBytes` op's answer. The fixture Ed25519 leaf certificate is presented; its
  private key is `certSeed`, so the CertificateVerify the client checks against the cert's public key
  verifies.
- `scripts/tls-interop.sh` drives two independent clients against it; both complete a TLS 1.3 handshake
  negotiating `TLS_CHACHA20_POLY1305_SHA256`:
  - **OpenSSL 3.0 `s_client`** — `New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256`;
  - **Python `ssl`** — `TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256`.
  Each validates kroopt's wire bytes end to end — ServerHello, the encrypted flight, the presented
  certificate, the CertificateVerify signature, and the server Finished — and sends its own
  change_cipher_spec + Finished, which kroopt verifies to reach `connected`.

**Honest scope.** This is handshake interop over a real OS socket — not yet over iotakt (the socket
helpers remain test-only glue) and not yet an application-data exchange (the server reaches `connected`
and closes; OpenSSL's `self-signed certificate` notice and post-handshake `unexpected eof` are both
expected, not failures). Full v0.3 acceptance still wants the iotakt-driven path, an app-data round-trip,
and the jemmet HTTPS E2E. But the protocol-structural claim is now externally validated: an independent
client accepts everything kroopt puts on the wire.

## [0.48.0-dev] — RFC 037 (native safety + budget enforcement) M37 band — 2026-06-13

### RFC 037 slice 8 — ASan/UBSan sanitizer target (§7.5; closes RFC 009/024 sanitizer deliverable)

- `scripts/sanitizer-check.sh` + `Kroopt/Native/kroopt_sanitizer_harness.c`: a sanitizer harness compiled
  with system gcc under `-fsanitize=address,undefined` (the Lean-bundled clang ships no ASan runtime),
  linking the Lean runtime so it can hand genuine `ByteArray`s to the shim. Two complementary halves:
  - **Buffer bounds (tight ASan).** Direct HACL\* calls on malloc-backed, exact-size buffers — `out = mlen+16`
    for AEAD seal, `len` for HKDF-expand, etc. — so any read past an input or write past an output is caught.
    Verified live by a negative control: under-sizing the AEAD output by one byte triggers a heap-buffer-overflow
    write. (Lean's own allocator places `ByteArray` data outside ASan's redzones, so this malloc-backed half is
    what gives real bounds coverage of the crypto I/O.)
  - **Real shim (UBSan + behaviour).** Calls the actual `kroopt_ffi_*` entry points with Lean `ByteArray`s,
    exercising the production marshalling/length-guard code under UBSan, with KAT (SHA-256, Ed25519 RFC 8032)
    confirming correct wiring and boundary cases (wrong-size keys, sub-tag ciphertext, tampered tag) confirming
    the fail-closed guards.
- Docs: the FFI-boundary trust assumption (RFC 009/024) is now partly discharged — `crypto-ffi-contract.md`
  and `proof-assumptions.md` record that the shim and the HACL\* calls it issues run clean under ASan/UBSan on
  KAT and adversarial inputs.

This closes the M37 native-hardening band (RFC 037 §2/§3/§5/§6-sending complete, §4 substantial). Deferred
with rationale: the C-owned zeroizing arena (before any production/stable claim), §4.1 crypto-op count/lifetime
bounds and config-sourced limits (with the async-crypto work), and inbound alert level/description parsing.

### RFC 037 slice 7 — graceful close seals and sends an encrypted close_notify (§6)

Before this slice the server sent no close_notify at all: a graceful close just transitioned state and
dropped the transport, leaving a peer unable to distinguish a clean close from a truncation. RFC 8446
§6.1 requires an encrypted close_notify under the current epoch first.

- `Kroopt/Core/Step.lean`: a graceful close from `connected` now seals a close_notify (level warning = 1,
  description close_notify = 0) under the application write epoch, reusing the same AEAD-seal action as
  application data — it advances the write sequence and emits `callCrypto (aeadSeal …)` rather than an
  immediate `closeTransport`. Before `connected` there is no application epoch, so the transport still
  closes directly.
- `Kroopt/Core/RecordPath.lean`: when a sealed record returns and a graceful close is in flight
  (`closeState = .sentCloseNotify` — the only outstanding seal at that point), the `.aeadSealed` handler
  writes the record and then closes the transport. Otherwise it is application data and is just written.
- Proofs: `appClose_no_emit` (Closure) and the appClose / cryptoResult cases in `ActionDiscipline` and
  `RecordPath` were repaired for the new nested matches. All stay true — a close_notify is a
  `callCrypto`/`writeTransport`/`closeTransport`, never `emitPlaintext`/`acceptPlaintextBytes` — so the
  no-early-/no-after-close-plaintext guarantees are unchanged. 94 public theorems, axioms unchanged.
- `Tests/Correspondence.lean` (33 checks): a core-level check confirms the close_notify is sealed with
  inner plaintext `[1, 0, alert]`; an end-to-end check drives the close through the production interpreter
  and confirms a sealed record (outer type `0x17`) is written before the transport closes.

Remaining in §6: inbound alert records still use minimal handling (begin close); deterministic
level/description parsing (close_notify vs fatal) feeding the close state machine is deferred. All
suites, fuzz, and both interop scripts green. No release.

### RFC 037 slice 6 — secret-arena classification + terminal-path leak tests (§3)

The honest part of §3 for the constrained dev/interop milestone: the Lean `SecretArena` is tolerated
only if the trust matrix states its *real* guarantee and secret-leak tests cover every terminal path.
This also closed a live gap — nothing dropped a connection's secrets on teardown, and `releaseSecret`
was a no-op.

- `Kroopt/Conn/Interpreter.lean`: a `terminate` helper marks the runtime terminal and drops every live
  secret reference via `SecretArena.bumpGeneration` (drops the stored bytes, invalidates outstanding
  handles). Every terminal arm now routes through it — `closeTransport` (all modes), `failWithAlert`,
  `reportError`, the wrong-kind crypto-result guard, and the §5 oversize-record failures. The
  `releaseSecret` arm now honours the action (`arena.release`) instead of no-op'ing.
- `Tests/Correspondence.lean` (31 checks): five secret-leak checks assert that after a graceful, fatal,
  or abortive close, a fatal alert, or a reported error, the runtime arena holds no live secret material
  (precondition: a keyed arena with `liveCount > 0`).
- Docs (`threat-model.md`, `proof-assumptions.md`): the secret-memory property is classified honestly as
  **TESTED / best-effort, not zeroization-guaranteed**. The interpreter drops references on terminal but
  does not overwrite memory; guaranteed zeroization is the job of the C-owned zeroizing arena (RFC 013
  §13.4), the fixed target whose timing is staged. **No production zeroization guarantee is claimed**
  until it lands.

Per §3, the C zeroizing arena remains required before any production/stable claim — that is deferred,
not done here. All suites, fuzz, and both interop scripts green. No release.

### RFC 037 slice 5 — `sealRecord` enforces the 2^14 record bound (§5)

`Record13.sealRecord` computed the record length with a truncating `ctLen.toUInt16` cast: an
oversize fragment (e.g. a misconfigured >16 KB certificate chain) would silently wrap to a wrong
length header and emit a malformed record. Per RFC 037 §5 it now **enforces** the bound.

- `Kroopt/Conn/Record13.lean`: `sealRecord` rejects content above `maxRecordPlaintext` (2^14, RFC 8446
  §5.1) *before* sealing, returning `Except ResourceLimitError ByteArray` (typed `recordSize` error).
  A `sealRecord!` convenience (panics on oversize) is provided for known-small test fixtures only.
- `Kroopt/Conn/Interpreter.lean`: the failure is propagated without weakening security. `sealHandshakeRecord`
  now returns `Except _ (Option ByteArray)` — distinguishing *sealed* from the transitional *no-key*
  case from *oversize*; `handshakeWire` maps no-key to the cleartext fallback but oversize to a typed
  error; the `writeHandshake`/`writeCertificate` interpreter arms turn that error into a terminal
  connection failure. Crucially, an oversize handshake message can no longer fall through to the
  keyless cleartext path (which would have leaked it unencrypted) — it fails the connection.
- Tests: `Tests/Record13.lean` (13 checks) — oversize content is rejected (`error recordSize`), content
  at the 2^14 bound still seals; existing `sealRecord` test/diagnostic call sites migrated to
  `sealRecord!`, and the `handshakeWire` correspondence checks adapted to the `Except` result.

Acceptance criterion §7.4 met. Legitimate records (handshake flight, ≤2^14 app fragments) are unaffected
— all suites, fuzz, and both interop scripts (which drive the real seal path) green. No release.

### RFC 037 slice 4 — ClientHello-bytes budget charged in the core (§4)

Continues §4 with a tighter, ClientHello-specific bound. `onClientHello` (the `start → requestedServerRandom`
transition) now charges the ClientHello message's wire bytes against the ClientHello budget via the proven
`chargeClientHelloBytes` (16384, RFC 019) before negotiating — bounding a single oversized initial flight
more tightly than the cumulative total-handshake-bytes budget (slice 3). Exhaustion fails the handshake
terminally with the generic `internal_error` alert and emits no plaintext.

- `Kroopt/Core/Handshake.lean`: charge wired into `onClientHello`.
- `Kroopt/Proofs/Handshake.lean` + `Kroopt/Proofs/RecordPath.lean`: the five theorems that unfold
  `onClientHello` (legal-edge, no-emit, no-accept, no-aeadOpen, pending-plaintext) updated for the new
  nested charge `match` — the charge-error arm routes through `hsFail` (already proven to move along a
  legal edge, emit no plaintext, and clear `pendingPlainOut`), so the safety invariants carry through
  unchanged (still 94 theorems, no `sorry`).
- `Tests/Handshake.lean` (now 12 checks): an oversized ClientHello (20000 bytes) is rejected by the
  budget (`failed internal_error`); a normal ClientHello stays under budget and advances the handshake.

Legitimate handshakes (~200-byte ClientHello) are far under budget — all suites, fuzz, and both interop
unaffected. Still open in §4: extension-count / total-extension-bytes (needs the parser to surface the
count), decrypted inner-handshake bytes, pending-ciphertext, the §4.1 crypto-op bounds, and
config-sourced limits. No release.

### RFC 037 slice 3 — resource budgets charged in the core: total handshake bytes (§4)

`Core/Budget.lean` had proven charge/check functions (the DoS bound in `Kroopt.Proofs.Budget`) that
`step` never invoked — so the budgets were not, as RFC 037 §4 requires, charged on the core path
where proofs and tests can see them. This slice wires the first one in.

- `Kroopt/Core/RecordPath.lean`: the inbound handshake-record path now charges the record's bytes
  against the cumulative total-handshake-bytes budget via the proven `chargeHandshakeBytes`
  (limits from `ResourceLimits.standard`, RFC 019 defaults), threading the updated `BudgetState`
  through the core state. This is distinct from — and now fires before — the per-buffer reassembly
  cap. Exhaustion is a terminal, typed `resourceLimit` failure that emits no plaintext.
- `Kroopt/Core/Alert.lean`: `alertForResourceLimit` added to the centralized error→alert mapping —
  budget exhaustion maps uniformly to the generic `internal_error` so the alert leaks neither which
  budget was hit nor any detail (consistent with `sequenceOverflow`).
- `Kroopt/Proofs/Closure.lean`: `alertForResourceLimit_is_fatal` and `…_not_closeNotify` proved, so
  the new mapping upholds the standing invariant that every error alert is fatal and never the benign
  `close_notify` (94 public theorems, up from 92).
- `Tests/Correspondence.lean` (now 26 checks): the over-large handshake input previously rejected by
  the buffer cap is now shown to fail specifically via the core budget charge (`failed internal_error`),
  pinning that the proven budget machinery is the active guard.

Scope: this charges the **plaintext** handshake-record path (the inbound ClientHello and any
handshake fragmentation — the pre-encryption attacker surface). Still open in §4: charging decrypted
inner-handshake bytes, the ClientHello-specific / extension-count budgets, pending-ciphertext, and the
§4.1 crypto-op count/bytes/lifetime bounds; and sourcing limits from validated config rather than the
standard defaults. The legitimate handshake (~200 inbound bytes) is far under budget — all suites,
fuzz, and both interop scripts unaffected. No release.

### RFC 037 slice 2 — FFI length contracts complete: the no-failure-channel primitives (§2)

Completes §2 by extending length validation to the primitives that produce output unconditionally and
so had no way to signal rejection. Consistent with the shim's existing CSPRNG convention (a failed draw
returns a zero-length `ByteArray`), each now returns the **empty** fail-closed sentinel on a length
violation rather than casting a bad length into the `uint32_t` HACL parameter:

- `aead_seal` (key = 32, nonce = 12, AAD/plaintext ≤ `UINT32_MAX`);
- `ed25519_sign` (private key = 32, message ≤ `UINT32_MAX`); `ed25519_public`, `x25519_public`
  (private key = 32);
- `hkdf_extract` / `hkdf_expand` (salt/ikm and prk/info ≤ `UINT32_MAX`); `hmac256` (key/msg);
  `sha256` / `sha384` / `sha512` (input ≤ `UINT32_MAX`), via a shared `len_u32_ok` helper.

For well-formed kroopt inputs every guard is unreachable, so no production behaviour changes; the
checks are defense-in-depth at the trust boundary (the C shim no longer trusts Lean-supplied lengths
for memory safety). `Tests/Hacl.lean` (now 26 checks) adds five more fixed-size negative cases
(wrong-size key/nonce on seal; wrong-size private key on sign and on both public derivations), each
asserting the empty result. KATs, tamper rejection, and both interop scripts — which drive the real
seal/sign paths with valid lengths — are unaffected.

**§2 is now complete:** every native primitive validates all input lengths and rejects (never
truncates) violations — status-tagged for the failure-channel primitives (slice 1: `aead_open`,
`x25519_shared`, `ed25519_verify`), empty-sentinel for the rest (this slice). Acceptance criterion
§7.1 is met. Remaining RFC 037: §3 secret-arena classification, §4 core-side budget charging +
crypto-op bounds, §5 `sealRecord` size enforcement, §6 close_notify/alert polish, §7.5 sanitizer
target. Proofs untouched (92 theorems). No release.

### RFC 037 slice 1 — FFI length contracts on the failure-channel primitives (§2)

Opening the M37 native-hardening band (the gate, with RFC 031, before live-client interop). The
native shim cast every `ByteArray` length straight to the `uint32_t` HACL parameter with no
validation. RFC 037 §2 requires validating every length **before** each HACL call and rejecting
(never truncating) anything that does not fit the expected fixed size or the `uint32_t` bound.

This slice hardens the three attacker-facing primitives that already carry a failure channel, so the
change is purely additive — a length violation is indistinguishable to the caller from a normal
cryptographic failure, and fails closed:

- `kroopt_ffi_aead_open` (ChaCha20-Poly1305): rejects key ≠ 32, nonce ≠ 12, AAD length > `UINT32_MAX`,
  or message length > `UINT32_MAX` → status 1 → `chachaPolyOpen` returns `none`. No plaintext is
  emitted on a malformed call.
- `kroopt_ffi_x25519_shared`: rejects a private scalar or peer point ≠ 32 bytes → status 1 → `none`.
- `kroopt_ffi_ed25519_verify`: rejects public key ≠ 32, signature ≠ 64, or message > `UINT32_MAX`
  → result 0 (invalid).

`Tests/Hacl.lean` (now 21 checks) adds six negative-length cases — wrong-size key/nonce on AEAD open,
wrong-size scalar/point on X25519, wrong-size public key/signature on Ed25519 verify — each asserting
the call fails closed. Positive KATs, tamper rejection, and both interop scripts (`ed25519-interop`,
`record-interop`) are unaffected, confirming the guards do not perturb the legitimate paths.

Still open in §2: the primitives with **no** failure channel (`aead_seal`, `ed25519_sign`,
`hkdf_extract`/`expand`, `hmac`, the SHA family, `*_public`) need a status-tagged return or a
caller-side length pre-check before they can reject malformed input — the next §2 slice. No production
behaviour changed for well-formed input; proofs untouched (92 theorems). No release.

## [0.47.0-dev] — RFC 031 (production-interpreter correspondence) milestone: `RealHandshake` retired — 2026-06-13

### RFC 031 — `RealHandshake` reduced to nothing: the production interpreter owns the real handshake

The RFC 031 milestone criterion (§5/§7.5): the bespoke `Tests/RealHandshake.lean` RD driver — with its
own flight assembly, transcript substitution, and record sealing — is **deleted**. Everything it was
built to exercise is now demonstrated by the **production interpreter** (`Kroopt.Conn.Interpreter`)
driving the real `Kroopt.Core.step` to `connected`, in `Tests/Correspondence.lean`.

- Deleted `Tests/RealHandshake.lean` (461 lines) and its `kroopt-realhandshake-test` executable. No
  alternative protocol driver remains in the test tree — the only handshake driver is the production one.
- Extracted the shared real fixtures (x25519 client share, server ECDHE private, ServerHello Random,
  Ed25519 certificate key + OpenSSL-parseable X.509 DER, `RealCryptoConfig`, ClientHello) into
  `Tests/RealFixtures.lean` (new `KrooptTestSupport` lib), so they live in exactly one place.
- Migrated the unique coverage into `Tests/Correspondence.lean` (now 25 checks), all production-driven:
  - a wrong client Finished is rejected — the real `verifyFinished` MAC check fails and the handshake
    does not reach `connected`, while the correct one does (check 21);
  - RFC 033 reassembly: a ClientHello split across two records reassembles to the same state as one
    record (22); an over-large reassembly buffer fails the connection (23); `frameHandshakeMessage`
    frames/reports-incomplete/splits-coalesced (24);
  - the certificate fixture is a well-formed DER object (25).
- The Ed25519 CertificateVerify *signing* path (RFC 8446 §4.4.3) remains gated cross-library by
  `scripts/ed25519-interop.sh` (HACL* ↔ OpenSSL); the record layer by `scripts/record-interop.sh`.
- Architecture docs updated: `live-handshake.md` carries an RFC 031 note that the RD driver is retired
  and the live handshake is demonstrated by `Tests.Correspondence`; `cert-presentation.md` and
  `record-protection.md` repointed to `Tests.RealFixtures` / `Tests.Correspondence`.

No production code changed in this step — it is a test-tree consolidation. Verification: full build;
4 gates (92 theorems; 36 pure-zone files); 23 test suites (the retired exe drops the count from 24);
fuzz 40000; both interop scripts.

**RFC 031 status.** Slices 1–9 plus the `RealHandshake` retirement land the protocol-correspondence
substance: real records sealed by the interpreter (§2), the core as single transcript authority (§3),
the crypto-op-id wrong-kind guard tested (§4), the §6 correspondence suite with the negative-bypass set,
and the §5/§7.5 driver-removal criterion. The §5 runtime **ledger** and the **async** §4 refinements
(duplicate/stale/after-terminal results) remain deferred: in the current synchronous interpreter the
properties they would witness are already pinned by the direct §6 checks, and the ledger's negative-space
value (no *unauthorized* effect) is best built alongside the async-crypto work where stale/duplicate
effects first become possible.

### RFC 031 slice 9 — §6 negative-bypass set: no application data accepted outside `connected`

Two more §6 negative-bypass checks, asserting at the interpreter layer that no application plaintext
is accepted outside the `connected` state — the only path to the interpreter's `acceptedBytes` is the
core's `acceptPlaintextBytes` action, which the core emits only from `connected`.

- `Tests/Correspondence.lean` (now 20 checks):
  - check 19 — an application send before `connected` (driven against a fresh handshaking state)
    accepts zero plaintext (`acceptedBytes == 0`); the core fails the send cleanly and emits no
    `acceptPlaintextBytes`;
  - check 20 — an application send after a graceful close has begun likewise accepts zero plaintext.

Together with slice 8 (wrong-kind crypto result → terminal; no plaintext emitted before `connected`),
the §6 negative-bypass set now covers the core bypass surfaces: wrong-kind results, early plaintext
emission, and early/after-close plaintext acceptance. No production code changed — tests pin existing
core guarantees as observed through the production interpreter. Proofs untouched (92 theorems);
`conn`/`https`/`e2e` unaffected. No release: the correspondence ledger (§5), the async §4 refinements,
and reducing `RealHandshake` remain before the RFC 031 milestone.

### RFC 031 slice 8 — §4 wrong-kind crypto-result guard tested; first §6 negative-bypass checks

The interpreter's §4 wrong-kind crypto-result guard (`resultMatchesKind`, wired into the `callCrypto`
arm) — which terminates with an internal-invariant failure rather than forward a provider result
whose kind cannot answer the requested op — now has explicit correspondence coverage, alongside the
first §6 negative-bypass checks.

- `Tests/Correspondence.lean` (now 18 checks):
  - check 16 — a provider that answers an ECDHE op with a signature result drives the interpreter
    to a terminal internal-invariant failure and forwards nothing (the mismatched result never
    reaches the core's result-kind dispatch);
  - check 17 — the guard is not over-eager: a correct-kind result is forwarded to the core unchanged
    and does not terminate the connection;
  - check 18 (§6) — through the entire server flight (paused at `sentServerFinished`, before
    `connected`), the interpreter has emitted no application plaintext.

No production code changed — these tests pin existing behaviour. Proofs untouched (92 theorems);
`conn`/`https`/`e2e` unaffected. The remaining §4 refinements (duplicate-result → fatal,
stale cross-generation → ignored+metric, result-after-terminal → released) concern asynchronous
crypto results, which the current synchronous interpreter never produces, so they land with the
async-crypto work. No release: those refinements, the correspondence ledger (§5), the rest of the
negative-bypass set (§6), and reducing `RealHandshake` remain before the RFC 031 milestone.

### RFC 031 slice 7 — complete the post-`connected` application-data wire path

The post-`connected` application send now produces a real `TLSCiphertext` record through the
production interpreter, fixing both gaps slice 6 surfaced:

- `Kroopt/Core/RecordPath.lean`: `handleAppSend` now seals under the **current** write sequence and
  advances afterwards (the read path is symmetric), so the first application record uses sequence
  number 0, not 1 (RFC 8446 §5.3 — a per-epoch sequence starts at 0). The state still advances by one
  per record, so the nonce/sequence proofs are unchanged (92 theorems).
- `Kroopt/Conn/Interpreter.lean`: the `writeTransport` arm — which the core emits only for sealed
  application ciphertext — now frames that ciphertext as a `TLSCiphertext` record by prepending the
  5-byte record header (`Record13.recordAAD` over the on-wire length, identical to the AEAD AAD the
  seal bound). All record framing now lives in the interpreter, the same place the handshake flight
  is framed via `Record13`.
- `Tests/Correspondence.lean` (now 15 checks): check 15 drives a real application send through the
  production interpreter, captures the produced record, and opens it with `Record13.openRecord` at
  sequence 0 — recovering the application plaintext. This exercises the sequence fix, record-header
  framing, and AAD together end to end.

`conn`/`https`/`e2e` unaffected (the fake provider's stub seal/open ignore the framing and keys).
Proofs untouched (92 theorems). No release: the crypto-op-id lifecycle (§4), correspondence ledger
(§5), negative-bypass tests (§6), and reducing `RealHandshake` remain before the RFC 031 milestone.

### RFC 031 slice 6 — symmetric aeadSeal AAD; post-`connected` app-data path scoped

`resolveRecordAAD` now binds the record-header AAD (RFC 8446 §5.2) for outbound `aeadSeal` ops as
well as inbound `aeadOpen`, reconstructing it from the on-wire ciphertext length (`plaintext.size`
plus the 16-byte Poly1305 tag, matching `Record13.sealRecord`'s `ctLen := inner.size + 16`).

- `Kroopt/Conn/Interpreter.lean`: `resolveRecordAAD` gains the `aeadSeal` arm.
- `Tests/Correspondence.lean` (now 14 checks): check 14 asserts `resolveRecordAAD` binds
  `recordAAD (plaintext.size + 16)` for an `aeadSeal` op. (The AAD value was also confirmed by a
  crypto round-trip during development — driving a real post-`connected` application send and
  opening the produced ciphertext with the reconstructed AAD.)

Driving a real application send through the production interpreter surfaced that the
post-`connected` application-data *wire* path is incomplete, independent of the AAD: (1) the core's
`aeadSealed` handler writes the bare sealed bytes via `writeTransport` with **no 5-byte record
header**, and (2) `handleAppSend` advances the write sequence with `seq.next` **before** sealing, so
the first application record is sealed at sequence number 1 instead of 0 (a TLS 1.3 violation — the
first record of an epoch must be seq 0). Both are masked by the fake provider (which ignores keys,
nonces, and AAD). Fixing them together — record-header framing for app ciphertext and the
first-record sequence number — with a full-record round-trip correspondence test is the next slice.

Proofs untouched (92 theorems). `conn`/`https`/`e2e` unaffected (fake provider ignores AAD). No
release: the app-data path, crypto-op-id lifecycle (§4), correspondence ledger (§5), negative-bypass
tests (§6), and reducing `RealHandshake` remain before the RFC 031 milestone.

### RFC 031 slice 5 — the production interpreter drives a full real handshake to `connected`

The §6.1/§7.2 headline: the production interpreter (`driveEvents`), given a real crypto provider,
now drives a complete TLS 1.3 handshake from an inbound ClientHello all the way to `connected` —
real ECDHE, real HKDF key schedule, a real Ed25519 CertificateVerify signature, real Finished
MACs, real record sealing, and a real inbound AEAD-open of the client's Finished. No test driver
substitutes any step; the bytes on the wire are the real flight.

- `Tests/Correspondence.lean` (now 13 checks): a real-ish provider (real crypto, with the
  ServerHello Random supplied as fixed test entropy since the pure provider draws none) drives the
  interpreter over `FakeTransport`. Check 12 asserts the handshake reaches `connected`; check 13
  asserts the wire flight is a cleartext ServerHello record (`0x16`) followed by four sealed
  protected records (`0x17`) for EncryptedExtensions/Certificate/CertificateVerify/Finished. The
  client Finished is computed from the interpreter's installed client handshake-traffic secret and
  the core's through-server-Finished transcript, sealed as a real `0x17` record, and opened by the
  core's `aeadOpen` op through the real provider.

- `Kroopt/Conn/Interpreter.lean`: **inbound AEAD-open AAD fix.** Driving a real sealed record
  through production surfaced that the core's record path hands `aeadOpen` an empty AAD, while the
  seal side (`Record13.sealRecord`) binds the record header as AAD per RFC 8446 §5.2 — so a real
  AEAD provider rejected every inbound protected record. The record header is a wire-framing detail
  the interpreter owns, so the new `resolveRecordAAD` reconstructs it from the on-wire ciphertext
  length (mirroring `Record13.recordAAD`) when forwarding `aeadOpen`. The fake provider ignores the
  AAD, so `conn`/`https`/`e2e` are unaffected; the real provider now opens the client Finished.

Proofs untouched (92 theorems). The post-`connected` outbound `aeadSeal` AAD is the same shape and
is the next small follow-up. This is not yet the full RFC 031 milestone (the crypto-op-id lifecycle,
the correspondence ledger, negative-bypass tests, and reducing `RealHandshake` remain), so no release
is cut.

### RFC 031 slice 4 — the interpreter hashes the core's carried transcript prefix

The production interpreter now resolves every transcript-bound crypto op by hashing the
**prefix bytes the core carried in it** (slice 3), and no longer maintains a transcript of its
own. This removes the slice-1 local accumulation that was outbound-only and missing the inbound
ClientHello, so the production path is now hashed over the complete, ClientHello-inclusive
transcript — the precondition for correct signatures/MACs against the real provider.

- `Kroopt/Conn/Interpreter.lean`: `resolveCryptoTranscript` drops its `transcript` parameter and
  hashes the op's carried field instead (`signCertificateVerify` input, `computeServerFinished` /
  `verifyFinished` transcript hash, and the traffic-secret `hkdfExpandLabel` contexts); `RuntimeState.transcript`
  and its accumulation in `writeHandshake`/`writeCertificate` are removed. The interpreter is now
  a pure hasher over core-supplied bytes — it never reconstructs the transcript.
- `Tests/Correspondence.lean` (11 checks): the resolution checks now feed an op carrying a known
  prefix and assert the resolved value is the SHA-256 of exactly those bytes; the wire-record,
  sealing, sequence, and ClientHello-inclusive checks are retained.

`conn`/`https`/`e2e` are unchanged — the fake provider ignores the resolved hash, and the
core-carried prefix is correct in the fake flow too (the core commits the parsed ClientHello and
the server messages regardless of provider). Proofs untouched (92 theorems).

### RFC 031 slice 3 — the core is the single transcript authority (ClientHello-inclusive)

The handshake transcript is held by the verified core, which commits the inbound ClientHello
and every server-flight message to its `TranscriptState.events` with exact wire bytes. Until
now the core passed only an *abstract* snapshot id (`#[snap.id]`) into transcript-bound crypto
ops, and the byte-accurate hash was reconstructed downstream — in the test driver from its own
seeded transcript, and (slices 1–2) in the production interpreter from an outbound-only
accumulation that was **missing the ClientHello prefix**. This slice makes the core carry the
real committed prefix bytes, so the authority lives in one place and the ClientHello is never
dropped.

- `Core/Transcript.lean`: new `TranscriptState.prefixBytes (snap)` reconstructs the exact bytes
  a snapshot pins — the concatenation of the first `snap.eventCount` committed events' wire
  bytes (ClientHello + the server messages committed before the snapshot).
- `Core/Handshake.lean`: the five transcript-bound op sites (handshake-traffic schedule,
  CertificateVerify, server Finished MAC, application-traffic schedule, client-Finished
  verification) now carry `ts.prefixBytes snap` instead of `#[snap.id]`. The snapshot pinning is
  already proved correct (`Proofs/Transcript.lean`: `snapshot_eventCount`,
  `snapshot_then_append_is_before`), so each op covers exactly the right prefix — including the
  client-Finished case, whose snapshot is taken before its own message is committed.
- The handshake legality proofs are unaffected (they discard the action list and reason only
  about the state), so the 92-theorem audit is unchanged.
- `Tests/Correspondence.lean`: new check (12 total) drives the core to the CertificateVerify op
  and asserts its carried prefix begins with the inbound ClientHello and extends past it — i.e.
  the op is hashed over `CH ++ ServerHello ++ EncryptedExtensions ++ Certificate`.

Nothing consumes the carried bytes yet — the interpreter still resolves against its own
accumulation, and the fake provider ignores the value — so `conn`/`https` are unchanged. The
next slice switches the interpreter to hash the core's carried prefix (and drops the incomplete
local accumulation), which is the precondition for reaching `connected` with the real provider.

### RFC 031 slice 2 — real record sealing in the production interpreter

The production interpreter now emits the **real encrypted flight**: a cleartext ServerHello
record followed by sealed EncryptedExtensions / Certificate / CertificateVerify / Finished
protected records, under the core-authorized write epoch and sequence number — no longer the
test driver's message-type heuristic and self-tracked `writeSeq` (the "alternative assembly"
RFC 031 §3 forbids).

- `Core/Action.lean`: `writeHandshake` and `writeCertificate` now carry `(epoch : Epoch)`
  and `(seq : UInt64)`. The core authorizes both: ServerHello is `.initial`/0 (cleartext);
  EncryptedExtensions/Certificate/CertificateVerify/Finished are `.handshake` at sequence
  0/1/2/3 (the flight order is fixed — no HRR — so the sequence numbers are constant literals
  in `Core/Handshake.lean`, decided by the core rather than counted by the interpreter). The
  four classifier `@[simp]` theorems are updated for the new arity; the proofs are otherwise
  untouched.
- `Kroopt/Conn/Interpreter.lean`: `writeHandshake`/`writeCertificate` realize each message as
  the wire bytes its epoch demands — `handshakeWire` frames the `.initial` ServerHello as a
  cleartext handshake record and seals `.handshake`-epoch messages with `Record13.sealRecord`
  under the server handshake-traffic key looked up from the arena, at the action's sequence
  number. The transcript still commits the *plaintext* message bytes, so the single transcript
  authority (slice 1) is preserved while the wire carries real records. A keyless arena (the
  transitional fake-provider path) falls back to a cleartext record rather than crashing.
- `Tests/Correspondence.lean`: grown to 11 checks — a sealed handshake-epoch message opens
  back to its plaintext under the installed key, honours the core-authorized sequence number
  (opens at seq 3, fails at seq 0), falls back to cleartext without a key, and keeps the
  ServerHello cleartext.

No proof change (92 public theorems; the action edits are binder-only at the classifier
theorems). The fake-provider `conn`/`https`/`e2e` suites are unaffected: they assert outbound
size/drain, not wire content, and the keyless fallback keeps them driving to `connected`.

### RFC 031 slice 1 — single transcript authority in the production interpreter

Begins RFC 031 (production-interpreter correspondence): the byte-accurate handshake moves
from the `Tests/RealHandshake.lean` driver into the production interpreter
(`Kroopt/Conn/Interpreter.lean`). This first slice establishes the **single transcript
authority** (RFC 031 §3): the interpreter accumulates exactly the serialized
handshake-message bytes it writes to the wire and binds every transcript-dependent crypto op
to the SHA-256 of those same bytes — never an independently assembled trace.

- `Kroopt/Conn/Interpreter.lean`:
  - `RuntimeState.transcript : ByteArray` accumulates the authorized handshake-message bytes.
  - `writeHandshake` / `writeCertificate` commit their serialized bytes to `transcript` as
    well as the wire, so the bytes written and the bytes hashed are one sequence.
  - new `resolveCryptoTranscript` substitutes the real `Hacl.sha256` of the current
    accumulated transcript into transcript-bound ops (`signCertificateVerify` via
    `certVerifyContent`, `computeServerFinished`, `verifyFinished`, and the traffic-secret
    `hkdfExpandLabel` contexts) before submission; non-transcript ops pass through. The flow
    ordering guarantees the accumulated transcript is at the correct point for each op, so no
    snapshot-id mapping is needed.
  - imports `Kroopt.Crypto.Hacl` and `Kroopt.Conn.Flight`; the interpreter is the impure
    layer and may compute real hashes.
- `Tests/Correspondence.lean` (new, RFC 031 §6 — grows with the RFC): 7 checks validating
  that the interpreter accumulates the serialized bytes as the transcript, that the wire
  bytes equal the hashed bytes, and that each transcript-bound op resolves to the real hash
  of exactly those bytes. New suite `kroopt-correspondence-test`.
- `lakefile.lean`: importing the HACL FFI into the widely-imported interpreter forces every
  interpreter-driving exe to link the native crypto lib; added `-Wl,--gc-sections` to those
  exe targets (conn, https, e2e, and the unit suites) to prune the unused HACL sections.

No behaviour change for the existing fake-provider `conn`/`https` suites: the fake provider
ignores the resolved transcript reference. Proofs untouched (92 public theorems); the change
is runtime-only.



Milestone release (RFC 032 "no first-byte dispatch" theme complete; RFC moved to
`rfcs/done/`). All five server-flight messages are emitted as typed `OutputAction`s and
serialized by a single source; the transcript is committed over those serialized bytes; a CI
gate forbids placeholder framers / first-byte dispatch in production. Accumulated over
session slices 4a–4d plus §5/§7 (below).

## [0.46.0-dev] — RFC 032 RESOLVED: transcript over serialized bytes + typed flight + CI gate — 2026-06-12

### RFC 032 slice 4a — server ECDHE share captured into the core

- `Core/State.lean`: `NegotiationState.serverShare : Option ByteArray`.
- `Core/Handshake.lean`: `onEcdheDone` now takes the server share from the
  `ecdheComplete` crypto result (previously discarded) and stores it in negotiation
  state — the prerequisite for emitting ServerHello as a typed core-authorized action
  (the share is now a core fact, not an interpreter-invented value). Transition shape and
  emitted actions are otherwise unchanged.
- Proofs/tests updated for the new `onEcdheDone` arity; theorem set unchanged (91,
  axiom-clean). `kroopt-realhandshake-test` (+1) asserts the core captures the 32-byte
  share and that it matches the value the interpreter sees.

### RFC 032 slice 4b — server Random drawn via a core op + handshake phase

- `Core/State.lean`: new handshake phase `requestedServerRandom`; `NegotiationState`
  gains `clientShare` (carried from the ClientHello) and `serverRandom`.
- `Core/Handshake.lean`: `onClientHello` now draws the server Random first — it stores
  the client share and requests a `randomBytes 32` op, moving to `requestedServerRandom`.
  New `onServerRandomDone` records the drawn Random and then requests ECDHE over the
  stored client share (`→ requestedEcdhe`). The server Random is now a **core value**
  sourced from the CSPRNG, not an interpreter-invented one — the second prerequisite for a
  typed ServerHello (RFC 032 §3). `legalEdge` gains the two new edges.
- `Core/RecordPath.lean`: the `randomBytes` crypto result, previously a no-op at the
  correlation layer, is now routed into the handshake gating dispatch so it reaches
  `onServerRandomDone`.
- Entropy stays an IO/interpreter-layer concern (RFC 034): the pure real provider still
  errors on `randomBytes`; the real-handshake driver supplies the fixed test Random.
- Proofs: `onServerRandomDone` `no_emit`/`no_accept` lemmas added and wired into the
  gating-dispatch proofs; per-transition legality holds via the new edges. Theorem set
  unchanged (91, axiom-clean). `kroopt-realhandshake-test` (+1, 30) asserts the core draws
  and holds the server Random; the manual `kroopt-handshake-test` phase trace now includes
  `requestedServerRandom`.
- *Still to do for typed ServerHello (slice 4c):* the typed `serverHello` action
  (`Wire.serverHello` over the now core-held Random + share + suite/group/version),
  `CipherSuite`/`NamedGroup` → `UInt16` wire encoders, and the driver's plaintext (no-seal)
  ServerHello path. The 32-byte Random length will be made wire-faithful there (the test
  Random fixture is presently 28 bytes; SH bytes are not yet wire-validated). Then Finished
  (MAC op), the §5 transcript restatement, and the §7 CI gate → milestone release.

### RFC 032 slice 4c — typed ServerHello action (4 of 5 flight messages typed)

- `Core/Action.lean`: `HandshakeOut.serverHello (random share : ByteArray) (suite group
  version : UInt16)` — every field a core value (Random from the core `randomBytes` op,
  share from the ECDHE result, suite/group from negotiation).
- `Core/Handshake.lean`: `cipherSuiteToU16` / `namedGroupToU16` wire encoders;
  `serializeHandshakeOut` serializes `serverHello` via `Wire.serverHello`. `onEcdheDone`
  now emits `writeHandshake (.serverHello …)` instead of `writeTransport` of placeholder
  bytes — **ServerHello is no longer recognized by a first byte anywhere on the production
  path.** Transcript commitment stays the abstract snapshot (unchanged), so the binding
  proofs are untouched.
- `Tests/RealHandshake.lean`: `appendRealHandshakeOut` now branches — ServerHello is
  committed **in the clear** (no AEAD seal, no handshake-record sequence consumed) and fixes
  the CH‥SH transcript hash; the rest of the flight stays sealed. The first-byte tag-2 path
  is now dead. The test server Random is a wire-correct 32 bytes.
- Four of five server-flight messages are now typed (ServerHello, EncryptedExtensions,
  Certificate, CertificateVerify); only Finished remains (its MAC op is slice 4d).
- Theorem set unchanged (91, axiom-clean). `kroopt-realhandshake-test` (30) confirms the
  emitted ServerHello equals the independently assembled real ServerHello and that the
  32-byte Random is core-held; e2e/conn/https complete through the production interpreter.

### RFC 032 slice 4d — typed Finished action (all 5 flight messages typed)

- `Core/Crypto.lean`: new `CryptoOp.computeServerFinished (alg) (transcriptHash)` (+ kind)
  and `CryptoResult.finishedMac (verifyData)` — the server Finished verify_data is computed
  by a purpose-typed core op (RFC 008 §4), the write-secret mirror of `verifyFinished`.
- `Core/Action.lean`: `HandshakeOut.finished (verifyData)`; `serializeHandshakeOut` emits
  `Wire.finished`.
- `Core/State.lean`/`Core/Handshake.lean`: new phase `requestedServerFinishedMac`.
  `onCertVerifySigned` now commits CertificateVerify, snapshots the transcript **through
  CertificateVerify**, and requests `computeServerFinished` over that hash (→
  `requestedServerFinishedMac`). New `onServerFinishedMac` commits Finished, resumes the
  application-key schedule **through Finished**, and emits the typed `finished` action
  carrying the core-computed verify_data (→ `sentCertificateVerify`). `legalEdge` gains the
  two edges. The `finishedMac` result is routed through the correlation layer into the
  gating dispatch.
- `Crypto/RealProvider.lean`: computes the verify_data = HMAC(server_finished_key, H) by
  looking up the **write** handshake-traffic secret; fake provider / `fakeCrypto` answer it.
- `Tests/RealHandshake.lean`: `substitute` maps the MAC's abstract ref to the real
  through-CV hash (`hCHCertVerify`); the typed Finished is sealed (it is) and fixes the
  CH‥SF hash. `kroopt-handshake-test` phase trace gains `requestedServerFinishedMac`.
- **All five server-flight messages are now typed** (ServerHello, EncryptedExtensions,
  Certificate, CertificateVerify, Finished). No production path recognizes any of them by a
  first byte. Theorem set: +1 public (`onServerFinishedMac_legal`, 92), axiom-clean; 24/24
  suites; the real and production interpreters complete the handshake with the
  core-computed Finished MAC.
- *Remaining before the milestone release:* §5 transcript restatement (commit the typed
  serialization to the transcript instead of the abstract `frame*` placeholders) and the §7
  CI gate forbidding placeholder framers / first-byte dispatch (it can pass only once §5
  removes the placeholders from production). Plus removing the now-dead `appendReal`
  first-byte dispatch in the test driver.

### RFC 032 §5 — transcript over serialized handshake bytes; §7 — CI gate

- `Core/Handshake.lean`: the transcript now commits the **typed serialization** of each
  server-flight message (`serializeHandshakeOut` for SH/EE/CV/Finished; new
  `serializeServerCertificate` for Certificate — empty DER until RFC 031, matching the
  emitted `writeCertificate`), not the abstract `frame*` placeholders. Each message is built
  once and used for both the transcript contribution and the emitted action, so the two
  agree by construction (RFC 032 §5; the §15.6 transcript guarantee now reads over serialized
  handshake-message bytes). The `frameServerHello`/`frameEncryptedExtensions`/
  `frameCertificate`/`frameCertificateVerify`/`frameServerFinished` placeholder functions are
  removed.
- `Tests/RealHandshake.lean`: the dead `appendReal` first-byte dispatch helper is removed;
  `writeTransport` now appends ciphertext to outbound without inspecting a first byte.
- `scripts/check-no-placeholder.sh` (new, RFC 032 §7): fails the build if any production
  module under `Kroopt/` contains a placeholder framer name or a first-byte
  handshake-dispatch helper. Wired into the gate suite; green.
- The generic transcript-binding proofs (`appendFramed_binds_exact_bytes`, ordering,
  snapshot-before-append) are unchanged and now guarantee consistency over the serialized
  handshake-message bytes. 92 public theorems, axiom-clean; 24/24 suites; fuzz 40000; both
  interop green.

## [0.45.0-dev] — M36 (RFC 032 slice 3): typed Certificate action — 2026-06-12

Third step of RFC 032: Certificate becomes a typed action. Because the core holds only an
opaque chain handle (no DER), the interpreter owns the DER resolution.

### Added

- `Core/Action.lean`: `OutputAction.writeCertificate (conn) (chain :
  CertificateChainHandle)` (a distinct action, not a `HandshakeOut` case, since its bytes
  are not pure-serializable), with classifier simp lemmas. Action now imports
  `Core.Cert` for the handle type (cycle-free).

### Changed

- `Core/Handshake.lean`: `step` emits `writeCertificate (selectedCert)` rather than a
  placeholder `writeTransport`. The abstract transcript contribution is unchanged.
- `Conn/Interpreter.lean`: a `writeCertificate` arm serializes the Certificate from the
  handle. With no configured DER wired into the runtime yet (RFC 031), production
  serializes a structurally-valid empty Certificate instead of the four-byte placeholder.
- `Tests/RealHandshake.lean`, `Tests/EndToEnd.lean`: drivers resolve the handle to their
  configured chain (the real test cert / an empty Certificate) and bind the
  CH‥Certificate transcript hash, matching the placeholder path they replace.

### Proofs

- Theorem set unchanged (91, axiom-clean); the new constructor is handled by the existing
  wildcard classifiers.

### Tests

- 24/24 suites pass, including socket and wire (which validate server-flight bytes); the
  synthetic flight reaches `connected` with a byte-identical Certificate.

### RFC lifecycle

- **RFC 032** stays in `proposed/`. Three of five server-flight messages
  (EncryptedExtensions, Certificate, CertificateVerify) are now typed and first-byte-free.
  Remaining: ServerHello + Finished (need server-share / Finished-MAC crypto-op flow), the
  §5 transcript restatement, and the §7 CI gate.

## [0.44.0-dev] — M36 (RFC 032 slice 2): typed CertificateVerify action — 2026-06-12

Second step of RFC 032: CertificateVerify joins EncryptedExtensions as a typed
handshake-output action, realizing the two-stage request/write rule for it.

### Added

- `Core/Action.lean`: `HandshakeOut.certificateVerify (scheme : UInt16) (signature :
  ByteArray)`.
- `Core/Handshake.lean`: `sigSchemeToU16` (SignatureScheme → wire code point) and the
  CertificateVerify case of `serializeHandshakeOut`.

### Changed

- `Core/Handshake.lean`: `onCertVerifySigned` emits `writeHandshake (.certificateVerify
  <scheme> <sig>)` instead of a placeholder `writeTransport`. The signature is the core's
  own `signCertificateVerify` result and the scheme is a negotiated fact, so serialization
  is authorized by the typed write action — not by bare crypto-result arrival (RFC 032 §4
  two-stage rule). The abstract transcript contribution is unchanged.
- `Tests/RealHandshake.lean`: the typed-message driver refreshes the post-CertificateVerify
  transcript hash (over which the server Finished MAC is taken), matching the placeholder
  path it replaces.

### Proofs

- Theorem set unchanged (91, axiom-clean). `writeHandshake` continues to be handled by the
  existing wildcard classifiers; no proof edits.

### Tests

- 24/24 suites pass; the synthetic flight reaches `connected` with byte-identical
  CertificateVerify, and the Ed25519 CertificateVerify interop check is unaffected.

### RFC lifecycle

- **RFC 032** stays in `proposed/`. Two of five server-flight messages
  (EncryptedExtensions, CertificateVerify) are now typed and first-byte-free. Remaining:
  Certificate (interpreter owns DER behind the chain handle), ServerHello + Finished
  (need server-share / Finished-MAC crypto-op flow), the §5 transcript restatement, and
  the §7 CI gate.

## [0.43.0-dev] — M36 (RFC 032 slice 1): typed EncryptedExtensions action — 2026-06-12

First step of RFC 032 (Typed Handshake/Record Assembly Contract): the core begins emitting
typed handshake-output actions that carry protocol facts instead of placeholder frame
bytes, with a single pure serializer realizing the wire bytes. EncryptedExtensions is
converted; no path recognizes it by its first byte.

### Added

- `Core/Action.lean`: `inductive HandshakeOut` (slice 1: `encryptedExtensions (alpn :
  Option ByteArray)`) and `OutputAction.writeHandshake (conn) (msg : HandshakeOut)`.
  Classifier simp lemmas mark `writeHandshake` as neither a plaintext emit nor an ordinary
  transport write.
- `Core/Handshake.lean`: `serializeHandshakeOut`, the one pure serializer that realizes a
  typed handshake message into wire bytes (EncryptedExtensions → ALPN-bearing exts).

### Changed

- `Core/Handshake.lean`: `step` emits EncryptedExtensions as `writeHandshake
  (.encryptedExtensions <selected ALPN>)` rather than a placeholder `writeTransport`. The
  abstract transcript contribution is unchanged (real-bytes transcript is a later slice).
- `Conn/Interpreter.lean`, `Tests/EndToEnd.lean`, `Tests/RealHandshake.lean`: realize
  `writeHandshake` via total pattern matching on the typed message through the shared
  `serializeHandshakeOut` — no first-byte dispatch for EncryptedExtensions.

### Proofs

- Theorem set unchanged (91, axiom-clean). `writeHandshake` is handled by the existing
  wildcard classifiers and the `isPlaintextEmit_eq_true` lemma's `simp` branch; the
  action-discipline and transcript-consistency proofs hold without edits.

### Tests

- 24/24 suites pass. The synthetic server flight still reaches `connected` with identical
  EncryptedExtensions wire bytes (the typed path serializes byte-for-byte what the
  placeholder path produced); the e2e flight-count and seven-message-transcript checks are
  unaffected.

### RFC lifecycle

- **RFC 032** stays in `proposed/`; this lands acceptance criterion 1 for one message.
  Deferred to later slices: CertificateVerify (two-stage), Certificate (handle→DER in the
  interpreter), ServerHello + Finished (need server-share / MAC crypto-op flow), the
  transcript-over-real-bytes restatement (§5), and the placeholder/first-byte CI gate (§7).

## [0.42.0-dev] — M36 (part 6): handshake-message reassembler — RFC 033 complete — 2026-06-12

The bounded handshake-message reassembler lands, completing RFC 033 (Real-Client
Handshake Processing). A ClientHello fragmented across records now parses correctly.

### Added

- `Core/State.lean`: `handshakeReasm : ByteArray` — the handshake-message reassembly
  buffer, a plain `ByteArray` with a runtime cap (like `inboundCiphertext`).
- `Core/RecordPath.lean`: `frameHandshakeMessage` frames one complete handshake message
  (1-byte type, 3-byte length, body), returning the message and the unconsumed tail, or
  `none` while incomplete; `maxHandshakeReasmBytes` bounds the buffer.

### Changed

- `Core/RecordPath.lean`: the plaintext handshake branch of `handleTransportBytes` now
  accumulates record fragments into `handshakeReasm`, frames and processes one complete
  message, keeps the tail for the next record, and fails the connection (oversized-record
  alert) if the buffer exceeds the bound. Previously each record body was assumed to be
  one complete handshake message, so a fragmented ClientHello was rejected as truncated.

### Tests

- `kroopt-realhandshake-test` (+3 checks, 28 total): `frameHandshakeMessage` framing unit
  (complete / incomplete / coalesced-with-tail); a ClientHello split across two records
  reassembles to the same state as one delivered whole; an over-large reassembly buffer
  fails the connection.
- Fixed three synthetic client-Finished fixtures (`Tests/EndToEnd`, `Tests/Conn`,
  `Tests/E2EHttps`) that used a 2-byte length where a handshake message requires a 3-byte
  length, and one malformed-ClientHello fixture made complete-per-header so the parser
  (not the reassembler) rejects it. These were latent malformations the old lenient path
  ignored; the reassembler parses the header correctly and exposed them.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The three theorems that
  case-split `handleTransportBytes` hold over the new branch unchanged — the obligation
  is `pendingPlainOut` preservation. The earlier deferral cited a missing
  `ByteArray.extract` size bound; that premise was false (the buffer is unproven-size,
  capped at runtime), so no extract lemma was needed.

### RFC lifecycle

- **RFC 033** (Real-Client Handshake Processing) → `done/`, **Implemented (0.42.0-dev)**.
  All six M36 parts complete: protected client Finished in-core, capability-bound
  negotiation of all three parameters, ClientHello strictness, the CCS phase window, and
  the reassembler. RFC counts: done 22, proposed 16.

## [0.41.0-dev] — M36 (part 5): explicit change_cipher_spec phase window (RFC 033) — 2026-06-12

The compatibility-mode `change_cipher_spec` record is now confined to its RFC 8446 §5
window in the record path; the payload check was already present.

### Changed

- `Core/RecordPath.lean`: `handleTransportBytes` gates the `change_cipher_spec` branch on
  the handshake phase. A compatibility CCS is accepted-and-ignored only during an active
  handshake (after the ClientHello, before the client's Finished). A CCS before any
  ClientHello (`start`), after `connected`, or while closing/terminal is rejected as an
  illegal record (`unexpectedMessage`). The single-0x01 payload check (`classifyCcs`)
  was already in place.

### Tests

- `kroopt-close-test` (+3 checks, 19 total): a compatibility CCS during the handshake is
  accepted and ignored; a CCS before any ClientHello is rejected; a CCS after `connected`
  is rejected.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The three theorems that
  case-split `handleTransportBytes` (`buffered_plaintext_authenticated`,
  `aeadOpen_uses_read_keys`, `successful_open_increments_read_seq`) hold over the added
  branch unchanged.

### RFC lifecycle

- **RFC 033** — partial; stays in `proposed/`. One item remains: the bounded
  handshake-message reassembler (gated on a clean `ByteArray.extract` size bound).

## [0.40.0-dev] — M36 (part 4): ClientHello strictness on legacy fields (RFC 033) — 2026-06-12

The ClientHello parser now enforces two TLS 1.3 invariants on legacy fields it
previously parsed but ignored (RFC 8446 §4.1.2).

### Changed

- `Parse/Handshake.lean`: reject a ClientHello whose `legacy_version` is not 0x0303
  (TLS 1.3 carries version preference in `supported_versions`; the legacy field is
  fixed by the spec). Reject a ClientHello whose `legacy_compression_methods` is
  anything other than the single null byte (compression is forbidden in TLS 1.3).

### Tests

- `kroopt-hardening-test` (+2 checks, 18 total): a ClientHello with `legacy_version`
  ≠ 0x0303 is refused; a ClientHello offering non-null compression is refused. New
  `chBadVersion` / `chBadCompression` / `rejects` helpers.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The new checks are
  conditionals on already-parsed values; the parser bounds proofs are unaffected.

### RFC lifecycle

- **RFC 033** — still partial; stays in `proposed/`. Remaining: the handshake-message
  reassembler and explicit `change_cipher_spec` policy.

## [0.39.0-dev] — M36 (part 3): cipher-suite selection bound to provider capability (RFC 033) — 2026-06-12

Negotiation now selects the cipher suite from the client's offers *and* binds it to
what the provider can actually perform — completing the overlap-selection discipline
across all three negotiated parameters (suite, group, signature scheme).

### Changed

- `Parse/Handshake.lean`: `suiteOfU16` maps only `TLS_CHACHA20_POLY1305_SHA256` (0x1303),
  the suite the vendored provider performs; the AES-GCM code points map to `none` and
  are skipped by `selectSuite`. kroopt no longer negotiates a suite it cannot complete,
  even when the client lists it first. The map widens when a real AES provider lands
  (RFC 035).

### Fixed

- A latent inconsistency the test harness masked: with a `13 01 13 03` ClientHello (AES
  first), the core selected AES-128-GCM while the ServerHello and key schedule used
  ChaCha20-Poly1305. The core now selects ChaCha20, matching the schedule.

### Tests

- `kroopt-hardening-test` (+2 checks, 16 total): a ClientHello offering only AES-128-GCM
  is refused; a ClientHello listing AES-128-GCM before ChaCha20 negotiates ChaCha20
  (capability overlap, not first-offered). New `chWithSuites` / `negotiatedSuite` helpers.
- `kroopt-e2e-test`, `kroopt-conn-test`: the negotiated-suite assertions now expect
  ChaCha20-Poly1305 (they previously encoded the buggy AES-128-GCM selection).
- Three fake-provider fixtures (EndToEnd, Conn, E2EHttps) now offer ChaCha20 in their
  ClientHello, matching the real constrained profile.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). Suite selection is pure
  list folding over bounds-checked data; the parser bounds proofs are unaffected.

### RFC lifecycle

- **RFC 033** — still partial; stays in `proposed/`. Remaining: handshake-message
  reassembler, broader ClientHello strictness (`legacy_version`, etc.), and explicit
  CCS policy.

## [0.38.0-dev] — M36 (part 2): signature_algorithms overlap selection (RFC 033) + repo hygiene — 2026-06-12

The ClientHello parser now negotiates the signature scheme from the client's offers
instead of hardcoding it, plus repository-hygiene work (GitHub language classification,
README, docs layout).

### Changed

- `Parse/Handshake.lean`: **signature_algorithms overlap selection.** New
  `sigSchemeOfU16` / `selectSigScheme` / `offeredSigSchemes` read the client's offered
  schemes (extension 0x000d) and select Ed25519 (0x0807) only when the client offers
  it — mirroring `selectSuite`. `parseClientHello` no longer hardcodes
  `selectedSigScheme := .ed25519`; a cert-authenticating server with no acceptable
  overlap (no `signature_algorithms`, or only RSA/ECDSA) is rejected (RFC 8446 §4.2.3).
  This makes the constrained profile's interop limit explicit: kroopt rejects the
  RSA/ECDSA-only RFC 8448 §3 ClientHello rather than presenting an Ed25519 certificate
  the client cannot verify.

### Repository hygiene

- **`.gitattributes`**: the vendored `Kroopt/Native/hacl/**` (HACL*/EverCrypt with the
  KaRaMeL C runtime, ~26k lines) is marked `linguist-vendored`, so GitHub classifies
  the repository by its own Lean 4 sources rather than the borrowed C. Every byte and
  its license stay in the tree and in production builds; only the language-stats display
  changes. Our own ~330-line FFI/socket shim remains first-party and counted.
- **README.md** rewritten (247 → 108 lines): a concise hero/overview/quick-start/design-
  notes/docs structure replaces the run-on status line and the stale per-milestone wall;
  the per-milestone history now lives in this changelog and the ROADMAP.
- **docs/src/** reorganized into `architecture/`, `crypto/`, and `verification/`
  subdirectories (introduction stays at the root); `SUMMARY.md` and all inter-doc and
  top-level links updated and verified to resolve.

### Tests

- `kroopt-hardening-test` (+2 checks, 14 total): a ClientHello offering only ECDSA/RSA
  signature_algorithms is refused; a ClientHello with no signature_algorithms is refused.
- `kroopt-wire-test`: the RFC 8448 §3 ClientHello check now asserts the constrained
  profile **rejects** it (no Ed25519 overlap); the byte-level serialization and SHA-256
  transcript KATs over the raw RFC 8448 bytes are unchanged.
- Five fixtures (EndToEnd, Conn, E2EHttps, Hardening, Wire) updated to carry a realistic
  `signature_algorithms` extension.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The selection logic is pure
  list folding over already-bounds-checked extension data; the parser bounds proofs are
  unaffected.

### RFC lifecycle

- **RFC 033** — still partial; stays in `proposed/`. Remaining: handshake-message
  reassembler, broader ClientHello strictness, explicit CCS policy, and binding
  cipher-suite selection to the provider's presentation capability.

## [0.37.0-dev] — M36 (part 1): the client Finished opens in the core (RFC 033) — 2026-06-12

The receive-side blocker from the architecture review (deep-review blocker #2): the
core now processes the **protected client Finished in-core** instead of silently
dropping it, driving the handshake to `connected` entirely through `Core.step` with
no out-of-core decryption workaround. The no-unauthenticated-plaintext guarantee is
preserved and re-proved.

### Changed

- `Core/RecordPath.lean`: `readMeta` is **epoch-aware** (`epoch := s.readEpoch.epoch`).
  A protected record arriving in `sentServerFinished` is opened under the **handshake**
  read epoch; the opened inner message is routed through `handshakeOnPlaintextRecord`
  → `onClientFinishedBytes` → `verifyFinished` → `connected`. Inner application data
  before `connected` is fatal. The two pre-`connected` silent drops are gone.
- `Core/Handshake.lean`: **read-epoch correctness.** The read epoch stays `handshake`
  through `sentServerFinished` (only the server's *write* switches to application
  after its Finished) and becomes `application` when the client Finished verifies.
  Previously the application read epoch was installed too early.

### Proofs (91 theorems, all axiom-clean; was 87)

- `Proofs/RecordPath.lean`: re-proved `buffered_plaintext_authenticated` (no
  unauthenticated plaintext) over the new branch, via four new
  `pendingPlainOut`-preservation lemmas (`onClientHello_pp`, `onClientFinishedBytes_pp`,
  `handshakeOnClientHello_pp`, `handshakeOnPlaintextRecord_pp`).
- `Proofs/KeySeparation.lean`: `aeadOpen_uses_read_keys` now proves the honest
  property `meta.direction = .read ∧ meta.epoch = s.readEpoch.epoch` (opens use the
  current read epoch — handshake for the client Finished, application afterwards).
- `Proofs/Nonces.lean`: `successful_open_increments_read_seq` re-proved over the new
  branch (which buffers no plaintext).

### Tests

- `kroopt-realhandshake-test` (+4 checks, 25 total): the **sealed** client Finished is
  driven through `step`, asserting the core opens it under the handshake epoch, routes
  it to `verifyFinished`, reaches `connected`, and buffers no application plaintext.
- `kroopt-nonce-test`: `connectedState` now carries application epochs (faithful to the
  real connected transition).

### RFC lifecycle

- **RFC 033** — partial; stays in `proposed/`. Remaining: bounded handshake-message
  reassembler (fragmented/coalesced records), overlap-selection negotiation, ClientHello
  strictness, explicit CCS. The current fix handles a single-record-complete Finished.

## [0.36.0-dev] — M36-prelude: provider capability honesty + fail-closed entropy (RFC 034) — 2026-06-12

The immediate honesty fixes the architecture review asked to fast-track ahead of the
M36 correspondence work. The real provider no longer advertises crypto it cannot
perform, and entropy no longer fails open. No core or proof changes — the 87 theorems
and 36 pure-zone files are unchanged.

### Added

- `Kroopt.Crypto.Provider.realCapabilities` — the real provider's honest, constrained
  profile: `TLS_CHACHA20_POLY1305_SHA256`, X25519, Ed25519, SHA-256, OS CSPRNG. No
  AES-GCM, SHA-384, P-256, ECDSA, or RSA.
- `Kroopt.Crypto.ConfigCheck` — `requiredCryptoOfServerConfig` and
  `validateServerConfigCapabilities`, rejecting a config that requires out-of-profile
  suites/signature schemes with a typed `CapabilityError` (RFC 008 §3 / RFC 034 §2).
- `Kroopt.Crypto.Hacl.RandomResult` / `EntropyError` and a fail-closed `randomBytes`
  returning a typed result.
- `kroopt-capabilities-test` (8 checks): real profile rejects AES/ECDSA and accepts the
  constrained config; the fake profile still accepts AES (profiles differ); the real
  provider advertises the constrained profile; a `randomBytes` op reaching the real
  provider is a typed error; entropy is fail-closed and typed.

### Changed

- `mkRealProvider.capabilities` is now `realCapabilities` (was `fakeCapabilities`).
- The real provider's `randomBytes` operation returns a typed error instead of
  deterministic zeros — deterministic randomness can never enter the real provider.
- `kroopt_ffi_random` fails **closed**: on `getrandom` failure it returns a zero-length
  buffer (never a zero-filled buffer reported as success).
- `Provision.genEphemeralX25519` / `provisionRealConfig` fail closed with a new
  `ProvisionError.entropyFailure` rather than emit a zero or partial key.
- Docs: `crypto-ffi-contract.md` and `proof-assumptions.md` record the real capability
  profile and the fail-closed entropy guarantee.

### RFC lifecycle

- **RFC 034** — *Provider Capability Honesty and Fail-Closed Entropy* — moved to
  `rfcs/done/` (Implemented, 0.36.0-dev). The config-capability check's call-site at live
  listener startup is the one deferred mechanical item, tracked to RFC 010 / RFC 031.
- RFCs 031–037 amended per the RFC-set review (handshake-message reassembly, transcript
  precision, two-stage crypto actions, overlap-selection negotiation, the 034 split, new
  RFC 036 trace harness); archive layout fixed to `rfcs/proposed/`.

## [0.35.0-dev] — M35 TLS 1.3 records over a real OS socket — 2026-06-12

A full server flight now traverses a real OS socket and opens on the peer,
exercising the transport boundary with real kernel I/O for the first time. No core,
crypto, or proof changes — the 87 theorems are unchanged.

### Added

- `Kroopt/Native/kroopt_socket.c`: minimal, test-only `AF_UNIX` socketpair plus
  blocking read/write/close (no protocol logic), wired through the same IO FFI ABI as
  `randomBytes`. kroopt's production core still performs no syscalls; this glue exists
  only to drive a test over a real socket.
- `kroopt-socket-test` (`Tests/SocketHandshake.lean`): seals a server flight
  (cleartext ServerHello + four `TLSCiphertext` records for EE/Cert/CertVerify/
  Finished under the server handshake key), writes it to the socket, and a peer reads
  the records back and opens them; the peer's encrypted Finished and an application
  record then round-trip the other way — all over the socketpair (5 checks). Added to
  CI (now 22 suites).
- `docs/src/socket-transport.md`.

### Notes

This de-risks the transport binding with real kernel I/O. The production iotakt
socket adapter (RFC 010) and a live `openssl s_client` / `curl` handshake (RFC
015/026) remain: they run the same record layer over a real, non-blocking,
externally-driven peer.

## [0.34.0-dev] — M34 record-layer cross-implementation interop — 2026-06-12

An independent implementation now decrypts kroopt's TLS 1.3 records, establishing
that the record layer is standards-compliant rather than only self-consistent. No
core, crypto, or proof changes — the 87 theorems are unchanged.

### Added

- `kroopt-wire-dump` (`Tests/WireDump.lean`): emits real `Record13`-sealed records
  (a handshake EncryptedExtensions at seq 0 and application data at seq 1, under the
  RFC 8448 §3 server handshake-traffic secret) for an outside tool to open.
- `scripts/record-interop.sh`: Python's `cryptography` library independently derives
  the traffic key/IV (RFC 8446 §7.3 HKDF-Expand-Label), reconstructs the §5.3 nonce
  and §5.2 AAD, and decrypts kroopt's records — recovering the exact plaintext and
  inner content type, and rejecting a tampered record. Added to CI.
- `docs/src/record-protection.md`: a cross-implementation interop section.

### Notes

A non-kroopt implementation decrypting kroopt's records is interop-grade evidence for
the record layer (RFC 026, partial). A full `openssl s_client` / `curl` handshake
still awaits productionizing the interpreter and the iotakt socket transport
(RFC 010).

## [0.33.0-dev] — M33 real Ed25519 X.509 certificate presentation — 2026-06-12

The live handshake now presents a real, OpenSSL-parseable Ed25519 X.509 certificate
instead of a placeholder DER, and the OpenSSL cross-check ties that certificate to
the CertificateVerify signature. No core, crypto, or proof changes — the 87 theorems
are unchanged.

### Added

- `scripts/gen-test-cert.sh`: provisions a self-signed Ed25519 `CN=kroopt.test`
  certificate whose subject public key is kroopt's certificate key (the RFC 8032
  §7.1 key that also signs CertificateVerify), via an RFC 8410 PKCS#8 wrap of the
  raw seed.
- `Tests/RealHandshake.lean`: presents the real 351-byte certificate DER (`certDer`)
  in the Certificate message and checks it is a well-formed X.509 embedded at the
  expected offset, with the handshake still reaching `connected` (21 checks).
- `scripts/ed25519-interop.sh` step 5: OpenSSL parses kroopt's certificate, confirms
  the leaf public key extracted from it equals kroopt's signing key, and verifies a
  kroopt CertificateVerify signature under that extracted leaf key — the property a
  real client relies on.
- `docs/src/cert-presentation.md` (linked in `SUMMARY.md`).

### Notes

A real client could now parse kroopt's Certificate message and verify its
CertificateVerify. This is a prerequisite for `openssl s_client` / `curl` interop,
which still awaits productionizing the interpreter and the iotakt socket transport
(RFC 010). Certificate path validation (client role / mTLS) stays out of scope.

## [0.32.0-dev] — M32 encrypted flight on the wire (record protection in the send/receive path) — 2026-06-12

The live `step`-driven handshake now exchanges real TLS 1.3 records: the server
flight after ServerHello is sealed, and the inbound client Finished is opened, in the
interpreter layer, while the core works on plaintext (its design). No core, crypto,
or proof changes — the 87 theorems are unchanged.

### Added

- `Tests/RealHandshake.lean` now applies `Record13` record protection across the
  handshake (20 checks): the ServerHello goes in the clear; EncryptedExtensions,
  Certificate, CertificateVerify, and Finished are sealed as four real `TLSCiphertext`
  records under the server handshake-traffic key with handshake-epoch sequences 0–3,
  each verified to decrypt back to its plaintext message; the client's Finished
  arrives as a real encrypted record that the interpreter opens (with the client
  handshake-traffic key) to drive the core to `connected`. The ServerHello now
  advertises `TLS_CHACHA20_POLY1305_SHA256` so the negotiated record cipher matches
  the wire protection. The transcript hash remains over the plaintext messages.

### Notes

The wire is now genuine TLS 1.3 records, but the seal/open lives in the test driver
(not yet the production `Conn.Interpreter`) and records are exchanged in memory (not
over a socket). Folding this into the production send/receive path and the iotakt
socket transport (RFC 010) is next, enabling OpenSSL/curl interop (RFC 015 / 026).

## [0.31.0-dev] — M31 real TLS 1.3 record protection (ChaCha20-Poly1305) — 2026-06-12

Adds the record-protection framing that turns a message + content type into a real
`TLSCiphertext` and back, and demonstrates it end-to-end over the live handshake's
negotiated keys. The verified core and its 87 theorems are unchanged.

### Added

- `Kroopt/Conn/Record13.lean` (impure interpreter zone): `innerPlaintext`
  (`content || content_type || zero*`), `recordAAD` (the §5.2 TLSCiphertext header),
  and `sealRecord` / `openRecord` — ChaCha20-Poly1305 under that AAD with the
  per-record nonce (`IV XOR seq`), wrapping/unwrapping the outer
  `application_data` record and stripping padding on open. No plaintext escapes a
  framing or authentication failure.
- `kroopt-record13-test` (`Tests/Record13.lean`, 11 checks): round-trip, wire
  structure, ciphertext-not-plaintext, padding stripping, content-type recovery, and
  authentication failures (tamper, wrong key, wrong sequence — the nonce binds the
  sequence).
- `Tests/RealHandshake.lean` now protects a real application-data record under the
  server application-traffic key derived by the live handshake after `connected`
  (16 checks total), confirming the round-trip and that the body is ciphertext.
- `docs/src/record-protection.md` (linked in `SUMMARY.md`). CI runs 21 suites.

### Notes

ChaCha20-Poly1305 is the record cipher (no AES-GCM in the vendored HACL subset), so
these are self-consistent round-trips, not an RFC 8448 §3 (AES-128-GCM) replay. The
verified core does not yet emit seal/open actions for the handshake flight (still
assembled in the clear in the driver), and records are not yet driven over a socket;
wiring record protection into the core's send/receive path and the iotakt socket
transport (RFC 010) is next, enabling OpenSSL/curl interop (RFC 015 / 026).

## [0.30.0-dev] — M30 live `step`-driven handshake reaches `connected` — 2026-06-12

The live `step`-driven real handshake (M29) now runs to **`connected`**: the driver
feeds a real client Finished and the verified core completes the handshake. A
correctness fix to the secret arena was required; the verified core and its 87
theorems are unchanged.

### Changed

- `Kroopt/Crypto/Arena.lean`: base traffic-secrets are now keyed by
  `(Direction × Epoch)` instead of `Epoch` alone (matching how installed record
  keys are keyed). A TLS 1.3 server verifies the client's Finished with the **read
  (client)** handshake-traffic secret; keying by epoch alone let the read/write
  secrets overwrite each other. `recordBaseSecret` / `lookupBaseSecret` take a
  direction.
- `Kroopt/Crypto/RealProvider.lean`: `verifyFinished` looks up the read-direction
  handshake base secret and compares its HMAC against the verify_data extracted from
  the client Finished message body (the octets after the 4-octet handshake header).

### Added

- `Tests/RealHandshake.lean` now drives to `connected` (14 checks): captures the
  client and server hs-traffic secrets, computes a real client Finished
  (`HMAC(finished_key(client_hs_traffic), Transcript-Hash(CH‥ServerFinished))`),
  feeds it back, and confirms the core reaches `connected`; a negative control
  confirms a wrong client Finished is rejected.

### Notes

The full server handshake now completes through the verified core on real crypto
over real wire bytes. The flight messages are still assembled in the clear (not yet
sealed with the record AEAD keys); real record encryption, the iotakt socket
transport (RFC 010), and OpenSSL/curl interop (RFC 015 / 026) remain.

## [0.29.0-dev] — M29 live `step`-driven real handshake (real provider + real transcript) — 2026-06-12

Drives the verified core `Kroopt.Core.step` state machine through a server
handshake against the **real** crypto provider with a **real transcript** assembled
by `Kroopt.Conn.Flight`, to `sentServerFinished`. The verified state machine is
unchanged: the 87 theorems and the 36 pure-zone files are untouched.

### Added

- `Tests/RealHandshake.lean` (`kroopt-realhandshake-test`, 12 checks): a driver that
  runs each `callCrypto` against `RealProvider.submit` (real HACL X25519 / HKDF /
  Ed25519 / HMAC, threading a real `SecretArena`) and maintains a real transcript —
  recognising each server-flight placeholder by message type, assembling the real
  bytes via `Flight`/`Wire`, and substituting the real transcript hashes
  (`CH‥SH`, `CH‥Cert`, `CH‥ServerFinished`) at the crypto seam. It checks that the
  live core runs without error to `sentServerFinished`, emits the full real server
  flight (SH, EE, Cert, CertVerify, Finished, in order), and produces a **valid
  Ed25519 CertificateVerify over the real transcript** (verifies against the leaf
  key; rejected against a wrong hash). CI now runs 20 suites (`realhandshake`).
- `docs/src/live-handshake.md` (linked in `SUMMARY.md`).

### Notes

This is a self-consistent handshake, not a replay of RFC 8448 §3: kroopt's cert is
Ed25519 (no RSA/P-256 in the vendored HACL), so the ClientHello offers `ed25519`
and the transcript is kroopt's own. The certificate entry is an opaque placeholder
DER (real provisioning is separate); it does not affect the CertificateVerify, which
signs the transcript hash. Remaining toward live interop: client Finished →
`connected`, real record encryption, the iotakt socket transport (RFC 010), and
OpenSSL/curl interop (RFC 015 / 026).

## [0.28.0-dev] — M28 real server-flight assembler + Ed25519 CertificateVerify — 2026-06-12

Adds the interpreter-side component that turns negotiated parameters and real
crypto outputs into the exact server-flight wire bytes, and produces a **real**
Ed25519 CertificateVerify with kroopt's own key. No change to the verified state
machine: the 87 theorems and existing suites are unchanged.

### Added

- `Kroopt/Conn/Flight.lean` (impure interpreter zone) composing the M26/M27 wire
  serializers with HACL primitives: `transcriptHash`, `serverHelloMessage`,
  `serverFinishedVerifyData` / `serverFinishedMessage`, and the real
  CertificateVerify path (`certVerifyContent` / `signCertVerify` /
  `verifyCertVerify` / `certificateVerifyMessage`). The core holds only abstract
  handles (no DER, no signature, no MAC, no random); this module is where those
  real bytes are supplied.
- `kroopt-flight-test` (`Tests/Flight.lean`, 14 checks): the RFC 8446 §4.4.3
  CertificateVerify content construction (the format cross-validated against
  OpenSSL in `scripts/ed25519-interop.sh`); a real Ed25519 sign/verify round-trip
  that rejects a wrong transcript hash and a wrong key; the Ed25519 key anchored to
  the RFC 8032 §7.1 KAT; ServerHello assembly and the server `finished_key` /
  Finished MAC anchored to RFC 8448 §3. CI now runs 19 suites (`flight`).
- `docs/src/server-flight.md` (linked in `SUMMARY.md`).

### Notes

kroopt can now produce a complete, self-consistent server flight (a real Ed25519
CertificateVerify that verifies, a real Finished MAC over the real transcript).
Remaining toward live interop (RFC 010/015/026): call this assembler from the
`step`-driven interpreter — feed the real bytes into the transcript in place of the
placeholders in `Core/Handshake.lean` and resolve the core's transcript snapshots
to these real hashes at the crypto seam — then real record encryption, the iotakt
socket transport, and OpenSSL/curl interop.

## [0.27.0-dev] — M27 real server-flight serializers + server-Finished MAC KAT (RFC 8448 §3) — 2026-06-12

Extends the wire serializer (M26) to the **entire** TLS 1.3 server flight and adds
a real server-Finished MAC known-answer test. No change to the verified state
machine: the 87 theorems and existing suites are unchanged.

### Added

- `Kroopt/Parse/Wire.lean`: `certificate` / `certificateEntry` (RFC 8446 §4.4.2)
  and `certificateVerify` (§4.4.3) serializers, alongside the existing
  `serverHello` / `encryptedExtensions` / `finished`.
- `kroopt-wire-test` grew from 11 to **13 checks**, all against RFC 8448 §3:
  - **Framing** — ServerHello, EncryptedExtensions, Certificate, CertificateVerify,
    and Finished each serialize **byte-for-byte** to the trace. RFC 8448 §3 uses an
    RSA cert / RSA-PSS signature (outside the vendored HACL subset), so the
    432-byte cert DER and 128-byte signature are sliced from the vector and fed
    back as opaque inputs — the framing is validated, not the RSA math.
  - **Real server-Finished KAT** — `finished_key = HKDF-Expand-Label(server hs
    traffic, "finished", "", 32)` matches RFC 8448, and `verify_data =
    HMAC(finished_key, Transcript-Hash(CH ‖ SH ‖ EE ‖ Cert ‖ CertVerify))`
    recomputed over the *serialized* flight equals the RFC 8448 server Finished
    `verify_data` (`9b 9b 14 1d …`). Ties serializers + transcript + Finished MAC
    to the authoritative trace.

### Notes

Remaining toward real interop (RFC 010/015/026): sign CertificateVerify with
kroopt's own Ed25519 cert key (RSA stays out of scope); wire the serializers into
the live handshake transcript (replacing the `[snap.id]` placeholders in
`Core/Handshake.lean`); real record encryption; an iotakt socket transport; then
OpenSSL/curl handshake interop.

## [0.26.0-dev] — M26 real handshake wire serializer (RFC 8448 §3 byte-exact) — 2026-06-12

First increment of the structural→real wire work. Adds a real TLS 1.3 handshake
serializer and validates it byte-for-byte against an authoritative vector. No
change to the verified state machine: the 87 theorems and existing suites are
unchanged.

### Added

- `Kroopt/Parse/Wire.lean` — pure, total TLS 1.3 handshake wire serializers (the
  counterpart to the bounds-safe `Reader` parser): big-endian integers,
  length-prefixed vectors, the handshake header, extensions, and `serverHello` /
  `encryptedExtensions` / `finished`. Pure-zone module (now 36 clean); no proof
  obligations (serialization has no over-read risk).
- `kroopt-wire-test` (`Tests/Wire.lean`, 11 checks) validating against the
  **RFC 8448 §3 "Simple 1-RTT Handshake"** trace (vectors transcribed verbatim
  from rfc-editor.org, provenance recorded in-test):
  - `serverHello` serializes **byte-for-byte** to the 90-octet RFC 8448 ServerHello;
  - `SHA-256(ClientHello ‖ serialized ServerHello)` equals the RFC 8448
    CH‥ServerHello transcript hash the key schedule already derives over — the
    real-wire-bytes → real-transcript-hash join;
  - the existing `parseClientHello` accepts the real RFC 8448 ClientHello and
    extracts its x25519 `key_share` (parser is not over-strict on real input).
- `docs/src/wire-format.md` (linked in `SUMMARY.md`) describing the serializer,
  the RFC 8448 validation, and the remaining structural→real steps. CI test loop
  now runs `wire` (18 suites).

### Notes

This is step 1 of several toward real interop. Still pending (RFC 010/015/026):
real Certificate/CertificateVerify/Finished bodies, wiring the serializers into
the live handshake transcript (replacing the `[snap.id]` placeholders in
`Core/Handshake.lean`), real record encryption, an iotakt socket transport, and
OpenSSL/curl handshake interop. The placeholder frames remain in use by the
synthetic handshake until that wiring lands.

## [0.25.0-dev] — M25 RFC lifecycle migration (audit + `proposed/` → `done/`) — 2026-06-12

Governance only; no code, test, or proof change (87 theorems unchanged). Audits the
implementation RFCs against their own acceptance criteria per the RFC lifecycle policy
(RFC 000) and migrates the fully-shipped ones to `rfcs/done/`.

### Changed — RFC states

- Moved **19 RFCs** to `rfcs/done/` with `**Status.** Implemented (0.24.0-dev)`: 001–008,
  011–014, 016–019, 021–023. Each had every acceptance criterion met by shipped
  code/tests/proofs/gates in this repo.
- **11 RFCs remain in `rfcs/proposed/`**, each with one named open deliverable: 009 and
  024 (ASan/UBSan sanitizer CI), 010 (real iotakt socket transport), 015 + 026 (real
  OpenSSL/curl interop + HTTPS E2E), 020 (operator metric/event doc), 025 (benchmarks),
  027 (API-stability commitment), 028 (`SECURITY.md`), 029 (tested examples), 030
  (release runbook).
- Rebuilt `rfcs/README.md` as a state-grouped index (Done with "Shipped in" milestone;
  Proposed with the pending deliverable). RFC 000 invariants checked: folder/Status
  agreement, no duplicate numbers, every index link resolves, every file is listed.
  Cross-references are by RFC number in prose, so no link rewriting was needed.

## [0.24.0-dev] — M24 Ed25519 false-positive closeout (test-governance cleanup) — 2026-06-12

Final cleanup closing the Ed25519 false-positive incident, per architectural review. No
code-path or proof change; build green at 87 theorems. This is test-governance hardening,
not a cryptographic change.

### Changed — changelog hygiene

- Removed all standing "HACL broken / gcc miscompile / Edwards arithmetic defect" language
  from the M19–M22 entries, restructured them with proper version headers, and kept only
  the legitimate deliverables (connection provisioning; SHA-512 KAT hardening) plus a dated
  retraction pointer. The detailed correction remains in `[0.23.0-dev]`.

### Added — vector provenance + postmortem

- Provenance comments on every published crypto KAT (`Tests/Hacl.lean`,
  `Tests/Provision.lean`): source, section, input, and length. Round-trip /
  self-consistency checks are now explicitly labelled and never presented as standards
  conformance.
- `docs/src/postmortem-ed25519.md`: a short postmortem — *the expected value was wrong;
  test-vector provenance is now mandatory* — with the operational rule (verify vector
  provenance byte-for-byte before localizing a defect into the primitive, compiler, or
  FFI). Linked from `SUMMARY.md`.

### Unchanged

- The RFC 8032 KAT, the labelled non-RFC regression vector, and the OpenSSL
  `CertificateVerify` interop (a separate evidence layer) all remain from `[0.23.0-dev]`.
  Trust matrix unchanged: Ed25519 stays ASSUMED (inherited verified). Incident closed.

## [0.23.0-dev] — M23 Ed25519 "defect" retracted as a false positive; corrected + interop-validated — 2026-06-12

Retracts the M19–M22 "non-RFC-8032 Ed25519 defect." It was a **test-vector
provisioning error, not a HACL\*, compiler, or Edwards-arithmetic defect.** HACL\*
Ed25519 is RFC 8032 compliant. No functional protocol change; build green at 87
theorems. The legitimate work from those milestones — connection provisioning and the
SHA-512 KAT hardening — stands and is unaffected.

### Root cause of the false alarm

- The reproduction paired a **non-RFC seed** `9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f`
  with RFC 8032 §7.1 Test 1's **public key** `d75a9801…`, which actually belongs to a
  **different seed** `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`.
  HACL\* correctly derived `bcd55c06…` for the seed it was given.
- Every earlier "isolation" step (clamped scalar, base point, `2d`, optimisation,
  uint128, FFI) was internally valid but ran on the wrong seed, so it only ever
  confirmed HACL\*'s self-consistency — never an independently-provisioned RFC vector.

### Corrected (independent verification)

- HACL\* on the **correct** RFC 8032 §7.1 Test 1 seed reproduces the published public
  key `d75a9801…` **and** the signature `e5564300…` byte-for-byte. Confirmed by an
  independent RFC 8032 reference implementation and by OpenSSL.
- `kroopt-provision-test` now asserts the real RFC 8032 KAT (public + signature), a
  labelled non-RFC regression vector, and vector well-formedness/length discipline
  (**20 checks**, was 16). The old "tripwire" asserting non-compliance is removed.

### Added

- `Tests/Vectors/Ed25519Rfc8032.lean` (built via the new `KrooptTestVectors` lib):
  test vectors carry an explicit `source`, algorithm, and length-asserted hex; the RFC
  seed and the local regression seed are kept distinct so they cannot be re-mixed.
- `scripts/ed25519_hacl_cli.c` + `scripts/ed25519-interop.sh`: cross-library
  `CertificateVerify` interop — HACL\* and OpenSSL sign and verify each other's RFC 8446
  §4.4.3 signatures over a shared keypair, and both reject a tampered transcript. (Full
  `s_client`/`curl` handshake interop remains gated behind the pending real-handshake
  work.)

### Trust matrix

- **Unchanged.** Ed25519 stays **ASSUMED (inherited verified)**, with the RFC 8032 KAT
  and OpenSSL interop as **TESTED** evidence. No re-vendor, no compiler workaround, no
  unverified reference binding.

## [0.22.0-dev] — M21 (retracted Ed25519 investigation) — 2026-06-12

Recorded a now-**retracted** Ed25519 investigation. No code change and no functional
deliverable; its conclusions were a false positive caused by a mistyped RFC 8032 test
seed and are fully corrected in 0.23.0-dev. Build green at 87 theorems. Retained as a
dated placeholder for the audit trail — see 0.23.0-dev for the resolution.

## [0.21.0-dev] — M20 crypto KAT hardening (SHA-512 binding + value KATs) — 2026-06-12

### Added / changed — crypto KAT hardening

- Bound `Hacl.sha512` (FFI shim + `opaque`) and added a **SHA-512("abc") FIPS 180-4**
  value KAT; **upgraded SHA-384** from a size-only check to a value KAT. The HACL suite
  (`kroopt-hacl-test`) is now 15 checks. No new theorems (Crypto/Native zone); 87
  unchanged.
- Confirmed the vendored `Hacl_Ed25519.c` and its dependencies are byte-identical
  (`diff` = 0) to the pristine HACL\* 0.4.5 release at tag `ocaml-v0.4.5`.

> A suspected Ed25519 non-compliance investigated under this milestone was later found to
> be a **test-vector provisioning error (false positive)** — HACL\* Ed25519 is RFC 8032
> compliant (see 0.23.0-dev). The KAT hardening above is unaffected and stands.

## [0.20.0-dev] — M19 connection provisioning (`Kroopt.Crypto.Provision`) — 2026-06-12

### Added — connection provisioning (`Kroopt.Crypto.Provision`)

- `genEphemeralX25519 : IO (priv × pub)` draws a fresh ephemeral X25519 key pair from the
  OS CSPRNG (`Hacl.randomBytes`) per connection — no longer injected.
- `CertProvision` (signing seed, opaque DER chain, signature scheme) plus a deterministic
  config lint: `Provision.lint` checks seed length and scheme support and returns the
  *derived* leaf public; `lintAgainstClaimed` additionally rejects a mis-paired claimed
  public (`keyMismatch`), failing closed at load with a typed `ProvisionError`.
  `provisionRealConfig` assembles a `RealCryptoConfig` from linted certificate material
  and a fresh ephemeral pair.

### Changed — tests and CI (17 suites)

- New `kroopt-provision-test` covering ephemeral liveness / well-formedness / X25519
  determinism, the four lint branches, and the certificate-key sign+verify round-trip.
  Added to the verification loop and the CI test matrix. All 17 suites, parser fuzz, and
  the three gates green; theorem count unchanged at 87 (provisioning is `Crypto`-zone, no
  proof obligations).

> A suspected non-RFC-8032 Ed25519 defect reported under this milestone was later found to
> be a **test-vector provisioning error (false positive)** — a non-RFC seed paired with
> RFC 8032 Test 1's public key. HACL\* Ed25519 is RFC 8032 compliant (see 0.23.0-dev); the
> provisioning feature above is unaffected. The provision test's Ed25519 KAT is now a
> positive RFC 8032 KAT and the original "tripwire" was removed.



## [0.19.0-dev] — M18 wire the application-key schedule stage into live `step` — 2026-06-11

Completes the schedule wiring: `Kroopt.Core.step` now drives **both** stages of the
RFC 8446 §7.1 key schedule. After the CertificateVerify signature returns, the
handshake resumes the application-key stage instead of installing application keys
via a placeholder. The full synthetic handshake runs the entire schedule through
`step`.

### Changed — handshake drives the application-key stage (`Kroopt.Core`)

- `onCertVerifySigned` now frames CertificateVerify and the server Finished,
  snapshots the CH..server-Finished transcript, and calls `resumeApplication` to
  start the application-key stage (→ `sentCertificateVerify`) instead of jumping
  straight to `sentServerFinished` with a placeholder epoch install. (The transcript
  is committed only on the success path, so failure paths leave state untouched.)
- New `onApScheduleResult` pumps the application-key stage: each HKDF / install
  result advances the orchestrator and emits the next op, self-looping until
  `complete`, then installs the application epoch and moves to `sentServerFinished`.
- The gating dispatch routes `hkdfSecret` / `keysInstalled` to `onApScheduleResult`
  when in `sentCertificateVerify` (and still to `onHsScheduleResult` when in
  `derivedHandshakeSecrets`). `legalEdge` reroutes
  `requestedCertificateVerifySignature → sentCertificateVerify → sentServerFinished`.

### Changed — proofs (→ 87 theorems)

- New `onApScheduleResult_legal` (self-loops in `sentCertificateVerify` or advances
  to `sentServerFinished`, both legal). `onCertVerifySigned`'s legal / no-emit /
  no-accept proofs re-established for the nested `resumeApplication` match; the
  dispatch no-emit / no-accept proofs extended to the application pump. Global
  action-discipline and `connected_requires_finished_verified` unchanged. Axiom
  audit green; `{propext, Quot.sound}`.

### Changed — tests

- `kroopt-handshake-test` pumps both stages (5+2 then 4+2 schedule results) and
  checks the full seven-phase order through `sentCertificateVerify`; `kroopt-e2e-test`
  drives both via the generic fuel loop. All 16 suites, parser fuzz, and the three
  gates remain green.

### The honest boundary (next)

- The schedule's transcript contexts are still the core's abstract snapshot
  references, not real hash bytes, and the server Finished is synthetic rather than a
  real MAC — the wiring is structural. Real transcript resolution and the real
  Finished MAC are next, then production entropy / certificate provisioning, then a
  real handshake against OpenSSL/curl. See `docs/src/key-schedule-orchestrator.md`.



## [0.18.0-dev] — M17 wire the handshake-key schedule stage into live `step` — 2026-06-11

The verified orchestrator is now invoked by `Kroopt.Core.step`: the handshake
drives the handshake-key stage of the key schedule itself, gated and proved, rather
than installing handshake keys via a placeholder. The full synthetic handshake runs
the stage end-to-end through `step`.

### Added — schedule entry points (`Kroopt.Core.KeyScheduleDriver`)

- `startPostEcdhe` — the handshake-key stage entered post-ECDHE (the ECDHE op was
  already emitted and answered by the existing handshake), recording the shared
  handle and emitting the Early-Secret extraction. `emptyHashSha256` — the RFC 8446
  §7.1 empty-hash constant the schedule uses as Derive-Secret context.

### Changed — handshake drives the stage (`Kroopt.Core`)

- `State` gains `keySched : Option KeyScheduleDriver.State := none`, the active
  orchestrator while the schedule runs.
- `onEcdheDone` now frames ServerHello, installs the handshake epoch, and *starts
  the handshake-key stage* (→ `derivedHandshakeSecrets`) instead of jumping to the
  CertificateVerify request. New `onHsScheduleResult` pumps the stage: each HKDF /
  install result advances the orchestrator and emits the next op, self-looping until
  the `handshakeKeysInstalled` pause, then frames EncryptedExtensions / Certificate
  and requests the CertificateVerify signature (→ `requestedCertificateVerifySignature`).
- `handleCryptoResultCorrelated` now routes `hkdfSecret` / `keysInstalled` results
  to the gating dispatch (previously dropped); the dispatch forwards them to the
  pump when in `derivedHandshakeSecrets`. `legalEdge` reroutes
  `requestedEcdhe → derivedHandshakeSecrets → requestedCertificateVerifySignature`.

### Changed — proofs (→ 86 theorems)

- New `onHsScheduleResult_legal`: the pump self-loops in `derivedHandshakeSecrets`
  or advances to `requestedCertificateVerifySignature`, both legal. `onEcdheDone`'s
  legal/no-emit/no-accept proofs re-established for the new target; the dispatch
  no-emit / no-accept proofs extended to the pump (it emits only `callCrypto` /
  `writeTransport`, never plaintext). The global action-discipline and
  `connected_requires_finished_verified` proofs hold unchanged. Axiom audit green;
  `{propext, Quot.sound}`.

### Changed — tests

- `kroopt-e2e-test` and `kroopt-handshake-test` drive the schedule stage through the
  full handshake (e2e via the generic fuel loop; the direct-driven test pumps the
  seven stage results explicitly). All 16 suites, parser fuzz, and the three gates
  remain green.

### The honest boundary (next)

- The **application-key stage** is not yet driven by `step` (the orchestrator parks
  at `handshakeKeysInstalled`; application keys still use a placeholder) — wiring
  `resumeApplication` as a second pump phase after the server Finished is M18. And
  the schedule's transcript contexts are the core's abstract snapshot references,
  not real hash bytes; the wiring is structural, with real-transcript resolution a
  later milestone. See `docs/src/key-schedule-orchestrator.md`.



## [0.17.0-dev] — M16 two-stage (interleaved) key-schedule orchestrator — 2026-06-11

Corrects the orchestrator's derivation timing to match TLS 1.3. The M15 version
took both transcript hashes up front, which assumes the whole schedule runs at
once; in a real handshake the handshake-traffic keys are installed right after
ServerHello, but the application-traffic keys can only be derived after the server
Finished is committed (their transcript runs CH..server-Finished). The
orchestrator now pauses between the two stages, so it can be driven exactly the way
the live handshake will drive it. Still not invoked by `Kroopt.Core.step` — wiring
is the next milestone — so the existing handshake proofs remain untouched.

### Changed — orchestrator splits into two stages (`Kroopt.Core.KeyScheduleDriver`)

- `start` now takes only the suite, peer share, empty-hash, and the
  CH..ServerHello transcript (the application transcript is not yet known) and runs
  the **handshake-key stage** (ECDHE → … → install handshake keys), then parks at a
  new `handshakeKeysInstalled` phase. A crypto result delivered at the pause is
  held, not consumed.
- New `resumeApplication apTranscript` supplies the CH..server-Finished transcript
  once the server flight is committed and opens the **application-key stage**
  (Derive-Secret(handshake, "derived") → master → application-traffic secrets →
  install application keys → `complete`).

### Changed — proofs (→ 85 theorems)

- `advance_progress` now excludes both non-advancing phases (`complete` and the
  `handshakeKeysInstalled` pause). Added `advance_pause_inert` (the pause emits
  nothing under a crypto result), `resumeApplication_emits_schedule_ops`, and
  `resumeApplication_progress`. The schedule-ops-only and progress disciplines now
  cover both stages. Axiom audit green; `{propext, Quot.sound}`.

### Changed — test drives both stages (`kroopt-scheduledriver-test`, 12 checks)

- Stage 1 runs from `start` to the `handshakeKeysInstalled` pause and checks the
  handshake secrets and installed handshake `write_key`/`write_iv` against RFC 8448
  §3; `resumeApplication` then supplies the CH..server-Finished transcript and stage
  2 runs to `complete`, checking the Master and application-traffic secrets and all
  four installed traffic keys. Both stages run against the real provider.

### The honest boundary (next)

- The orchestrator now matches the handshake's interleaving but is still not
  invoked by `Kroopt.Core.step`. Faithful wiring is now two insertions: pump the
  handshake-key stage after ServerHello is framed, then `resumeApplication` and
  pump the application-key stage after the server Finished is committed. The
  handshake's safety proofs are absence-dominated and the orchestrator is proved to
  emit only schedule ops, so the integration is expected to preserve them. See
  `docs/src/key-schedule-orchestrator.md`.



## [0.16.0-dev] — M15 verified key-schedule orchestrator, driven through the real provider — 2026-06-11

Moves the *sequence* of the TLS 1.3 key schedule — which operation comes next,
with which handle as input — out of test code and into the verified core, as a
pure proved state machine. The orchestrator emits the schedule's ops and threads
the secret handles; the real provider answers them on HACL\*; the whole loop is
validated against the RFC 8448 §3 trace. It is not yet invoked by
`Kroopt.Core.step` — that integration is the next milestone — so the existing 78
theorems are untouched and four new ones are added (82 total).

### Added — key-schedule orchestrator (`Kroopt.Core.KeyScheduleDriver`)

- A pure core state machine: a fifteen-phase linear chain from the ECDHE share to
  the installed application keys. `start` emits the opening ECDHE op; each
  `advance` consumes the awaited result, records the handle it yields, and emits
  the next op (threading handles from each step into the next). Constructs
  `CryptoOp` values only — no crypto, IO, or FFI — so it sits in the verified core
  zone (deps gate: now 35 pure-zone files, clean).

### Added — proofs (`Kroopt.Proofs.KeyScheduleDriver`, +4 theorems → 82)

- `advance_emits_schedule_ops` — the orchestrator emits only ECDHE/HKDF/install
  ops, never AEAD, signature, or randomness ops (the discipline the `step`
  integration will rely on to preserve "no plaintext / no AEAD-open before
  connected").
- `advance_progress` — each accepted result advances the phase by exactly one
  rank, so the schedule is finite and cannot loop.
- `advance_complete_terminal` — `complete` is absorbing.
- `start_emits_schedule_op` — the opening op is itself a schedule op. All within
  `{propext, Quot.sound}`; axiom audit green.

### Added — orchestrator driven through the real provider (`kroopt-scheduledriver-test`, 11 checks)

- The orchestrator emits each op, `mkRealProvider` answers it on real HACL\* crypto
  threading the arena, and the result is fed back to `advance` for the next op,
  until `complete`. Every secret the orchestrator collected (read back from the
  arena by the handle it stored) and the installed handshake key/IV are then
  checked against the RFC 8448 §3 trace (ECDHE shared, Handshake/Master Secrets,
  server handshake/application traffic secrets, installed server-handshake
  `write_key`/`write_iv`, all four traffic-key installs present). Wired into CI.

### The honest boundary (next)

- The orchestrator is not yet invoked by `Kroopt.Core.step`. Wiring it into the
  live handshake — `onEcdheDone` and the gating dispatch kicking off and pumping
  the schedule, threading its state through negotiation — is the next milestone.
  The handshake's safety proofs are absence-dominated and the orchestrator is
  proved to emit only schedule ops, so the integration is expected to preserve
  them, but it does touch those proofs, which is why it is sequenced separately.
  See `docs/src/key-schedule-orchestrator.md`.



## [0.15.0-dev] — M14 enriched crypto interface + real provider driven through RFC 8448 §3 — 2026-06-11

Makes the crypto seam expressive enough to drive a real TLS 1.3 key schedule, and
ships a real `CryptoProvider` that performs a full handshake's cryptography
through the actual `submit` interface — validated against the RFC 8448 §3 trace
operation by operation. The verified core keeps handle opacity, so its 78
theorems hold over the enriched interface unchanged.

### Changed — enriched `CryptoOp` / `CryptoResult` (secret inputs named by handle)

- `hkdfExtract` now carries optional salt and IKM handles; `hkdfExpandLabel` now
  carries the input-secret handle, label, and context; a new `installTrafficKeys`
  op asks the provider to expand a traffic secret into the record key/IV and
  install them for a (direction, epoch). ECDHE now returns `ecdheComplete` (the
  server public share plus a shared-secret handle). The key schedule is now
  expressible as a handle-threaded chain.
- The AEAD operations are deliberately **unchanged** — still keyed by record
  metadata, with the provider resolving the installed key internally. Those are
  the only crypto shapes the proofs destructure, so leaving them fixed kept the
  proof migration empty.

### Unchanged — proofs

- All 78 machine-checked theorems hold over the enriched interface with no
  changes, and the axiom audit is identical: the proofs constrain operation
  *kind* and emission discipline, not secret payloads, and the AEAD shapes were
  preserved. Handle opacity intact (the core still sees only `SecretKeyHandle`s).

### Added — real provider (`Kroopt.Crypto.mkRealProvider`)

- Answers every enriched op with genuine HACL* cryptography, threading the arena:
  X25519 ECDHE, HKDF extract/expand resolving input handles, `installTrafficKeys`
  deriving and recording record keys (and the base secret for the Finished key),
  ChaCha20-Poly1305 record seal/open by installed key, real Ed25519
  CertificateVerify, and Finished-MAC verification. Static secrets it cannot
  itself produce (the server ephemeral X25519 key and the Ed25519 certificate
  key) are injected via `RealCryptoConfig`.
- `SecretArena` gained an installed-traffic-key index and per-epoch base-secret
  record so AEAD and Finished resolve keys without the core naming key bytes.

### Added — RFC 8448 validation through `submit` (`kroopt-realprovider-test`, 17 checks)

- Drives the real provider through the exact RFC 8448 §3 operation sequence via
  `submit` — the same calls the core will emit — and reads every produced secret
  back out of the arena to confirm it matches the published trace (ECDHE shared
  and server share, Early/Handshake/Master Secrets, all traffic secrets), checks
  the install path against the RFC's AES traffic key/IV, round-trips a real
  ChaCha20-Poly1305 record (with tamper rejection), verifies a real Ed25519
  signature, and accepts/rejects Finished MACs. Wired into CI.

### The honest boundary (next)

- The verified core does not yet *emit* this sequence — its handshake still emits
  the simpler op set. Making `Kroopt.Core.step` orchestrate the full schedule
  (threading the handles through negotiation state) is the next step; the
  interface and proofs are now ready, and the fixed AEAD shapes mean it should not
  disturb the safety proofs. Production entropy seeding and certificate
  provisioning through the interpreter remain a scoped follow-up. See
  `docs/src/enriched-crypto-interface.md`.



## [0.14.0-dev] — M13 provider-arena refactor: stateful crypto seam + real TLS 1.3 key schedule (RFC 8448-validated) — 2026-06-11

Makes the crypto seam stateful so real key material can flow, and builds the real
TLS 1.3 key schedule on the native HACL* primitives — validated against the
RFC 8448 §3 trace. The verified core and its 78 theorems are untouched: handle
opacity is preserved, so this adds a stateful trusted seam beside the proofs, it
does not modify them.

### Added — secret arena (`Kroopt.Crypto.SecretArena`)

- A bounded, generation-tagged store mapping `SecretKeyHandle` ids to secret
  bytes, threaded as a pure value (no hidden `IORef`). Handles carry the arena
  generation; a stale handle is rejected after `bumpGeneration`. Capacity-bounded
  (RFC 019); release/zeroize documented honestly as best-effort.

### Changed — stateful provider seam

- `CryptoProvider.submit` now threads the arena:
  `SecretArena → OperationId → CryptoOp → Except CryptoError (SecretArena × CryptoResult)`.
  The interpreter threads it through `RuntimeState.arena`. The fake provider
  allocates real handles from the arena (ECDHE/HKDF), so the existing handshake
  tests now exercise arena allocation end-to-end. All seam-affected suites stay
  green with no behaviour change.

### Added — real key schedule (`Kroopt.Crypto.KeySchedule`) and arena AEAD (`Kroopt.Crypto.Real`)

- The RFC 8446 §7.1 schedule on HACL*: HKDF-Expand-Label, Derive-Secret, the
  early/handshake/master chain, handshake/application traffic secrets, traffic
  keys/IVs, and Finished keys (SHA-256 suite).
- `Kroopt.Crypto.Real` installs derived keys into the arena under handles and
  seals/opens records by handle with the per-record nonce (RFC 8446 §5.3).

### Added — RFC 8448 validation (`kroopt-keyschedule-test`, 20 checks)

- The whole chain matches the RFC 8448 §3 "Simple 1-RTT Handshake" trace exactly
  (empty hash, Early Secret, X25519 from both sides, derived secrets, Handshake
  and Master Secrets, all traffic secrets, traffic keys/IVs, Finished key),
  computed through the native HACL* object code — plus a real-key arena AEAD
  round-trip with tamper rejection and stale-handle behaviour. Wired into CI.

### The honest boundary (next milestone)

- Not yet driven by `Kroopt.Core.step`: the core's `CryptoOp`s are too abstract
  to express a real schedule (no salt/IKM, no label/input handle, no AEAD key
  reference). Wiring it requires enriching those shapes and re-proving the
  operation-id correlation and no-emit/no-accept discipline over them, while
  keeping handle opacity. See `docs/src/key-schedule.md`.



## [0.13.0-dev] — M12 native crypto binding: HACL* primitives callable and KAT-verified through Lean — 2026-06-11

- The vendored HACL* generated C files are
  in fact under the **MIT** license
  (per their retained per-file headers,
  Copyright (c) 2016-2020 INRIA, CMU and
  Microsoft Corporation);
  the kremlin headers are **Apache-2.0**. `NOTICE` states this accurately.
- Added `Kroopt/Native/hacl/LICENSE` reproducing the full MIT text and the
  Apache-2.0 reference next to the vendored sources, a repository-root
  `THIRD-PARTY-NOTICES.md` with upstream/version/subset/no-modifications
  provenance, and a `docs/src/third-party.md` page. The vendored files remain
  verbatim with headers intact, which is what MIT requires.

### Changed — interface-first decoupling (depend on interfaces, not implementations)

- The transport dependency is now an explicit abstract interface,
  `Kroopt.Conn.Transport` (a typeclass: `recv`/`send`/`enableWrite`/
  `disableWrite`/`closeConnection` over a generation-protected `FdKey`). The
  interpreter (`drainOutbound`, `execAction`, `execActions`, `driveEvents`) is
  now **generic over `[Transport τ]`** and names no concrete transport.
  `FakeTransport` is the in-model instance; a real I/O reactor such as iotakt is
  simply another instance of the same interface.
- Removed concrete-project coupling from kroopt's contracts: **jemmet** (which
  depends on kroopt, never the reverse) no longer appears in any code contract —
  it survives only as an example consumer in prose. **iotakt** appears only as an
  example `Transport` instance. The upward plaintext adapter was renamed
  `PlainIotaktConn` → `PlaintextConn` to reflect that it is a plaintext (non-TLS)
  connection, not an iotakt-specific type.
- This reshapes the deferred transport work: rather than "wire kroopt to iotakt,"
  it becomes "provide an iotakt adapter as one `Transport` instance" — the same
  generic interpreter drives it unchanged.

Historical RFC documents under `rfcs/` retain their original iotakt/jemmet
framing as dated design records; the *contracts* (code and the boundary docs) are
now interface-first.



The first **native crypto** milestone (v0.3 binding). Vendors a portable-C subset
of HACL* (Project Everest), builds it through Lake, and calls the verified
primitives from Lean over a thin FFI — proving the real crypto path works
end-to-end, offline and reproducibly, inside the Lean build. This is the
primitives layer; wiring it into the stateful TLS key schedule is scoped as the
next step (a provider-arena refactor), documented honestly below.

### Added — vendored HACL* subset (`Kroopt/Native/hacl/`)

- A portable-C subset of HACL* covering exactly the `TLS_CHACHA20_POLY1305_SHA256`
  suite with X25519 and Ed25519: SHA-256/384, X25519 (public + ECDH with
  low-order rejection), ChaCha20-Poly1305, HKDF/HMAC-SHA256, Ed25519. No vale
  assembly (AES paths omitted) — pure portable C, reproducible on any C11
  compiler. License attribution added to `NOTICE` (Apache-2.0).

### Added — FFI glue and Lean wrappers

- `Kroopt/Native/kroopt_ffi.c`: boring buffer marshalling between Lean
  `ByteArray`s and the HACL* primitives; no crypto logic of its own.
- `Kroopt.Crypto.Hacl`: Lean wrappers — deterministic primitives as pure
  `@[extern]`, `randomBytes` as `IO` (OS CSPRNG via `getrandom`). Lives in the
  trusted `Crypto` zone; never imported by the pure verified core (deps gate
  unchanged: 33 pure-zone files clean).

### Added — build wiring and KATs

- `extern_lib krooptCrypto` in `lakefile.lean` compiles the vendored C + glue
  into `libkroopt_crypto.a`; `kroopt-hacl-test` links it (`--gc-sections` drops
  the unused agile-HMAC SHA-1/Blake2 variants).
- `Tests.Hacl` (14 checks): SHA-256 (FIPS 180-4), X25519 (RFC 7748), HKDF
  (RFC 5869 TC1), HMAC (RFC 4231 TC1), AEAD and Ed25519 round-trips with
  tamper/forgery rejection, CSPRNG length and non-constancy — all run **through
  the FFI** over the real HACL* object code.

### Documentation

- `docs/src/native-crypto.md`: the binding, the primitive map, and the honest
  boundary — why a *pure, handle-returning* `CryptoProvider.submit` cannot thread
  real key material through the key schedule, and what the next-step
  provider-arena refactor must do while preserving handle opacity for the proofs.

### Unchanged

- 78 machine-checked public theorems; all three proof gates green (hygiene,
  deps, axiom audit — no `sorryAx`, axioms within `{propext, Quot.sound,
  Classical.choice}`). The verified core and its proofs are untouched: this
  milestone adds a trusted native seam beside them, it does not modify them.
- The pure Lean core still builds with no C toolchain; only the FFI library and
  its KAT executable require a C compiler.

## [0.12.0-dev] — M11 cross-cutting hardening: resource budgets, scope control, threat model, axiom gate — 2026-06-11

Cross-cutting hardening milestone (RFC 016, 017, 019, 022). Adds the resource-
budget model with proved DoS bounds, deferred-feature scope control, the threat
model, and a third proof gate (axiom audit) wired into CI.

### Added — resource budgets (`Kroopt.Core.Budget`, RFC 019)

- `ResourceLimits` (configured ceilings) and pure charge primitives
  (`chargeHandshakeBytes`, `chargeExtensions`, `chargeProgressStep`,
  `checkRecordSize`, `chargePendingCiphertext`) returning typed
  `ResourceLimitError`.
- `Kroopt.Proofs.Budget` — six theorems: an accepted charge never exceeds its
  ceiling (`*_bounded`), over-limit input is rejected (`*_rejects_over`), and
  charges account exactly. The DoS bound is proved, not asserted.

### Added — proof gates and CI (RFC 022)

- `scripts/check-axioms.sh` — the semantic gate: `#print axioms` for every public
  theorem, asserting no `sorryAx` and axioms within
  `{propext, Quot.sound, Classical.choice}`. Audits 78 public theorems/lemmas.
- `.github/workflows/ci.yml` — runs build, all test suites, the fuzzer, and all
  three gates (hygiene, dependency, axiom) on push and PR.

### Added — scope control + threat model (RFC 016, 017)

- `Tests/Hardening.lean` (`kroopt-hardening-test`) — 12 checks: budget
  accept/reject/bound behaviour, and deferred-feature scope control (a ClientHello
  with no `supported_versions`, only TLS 1.2, or no key_share is refused — no
  silent downgrade, no HRR).
- Docs: `threat-model.md` (adversary + threat→defense map), `resource-budgets.md`,
  `deferred-scope.md`, `proof-gates.md`.

## [0.11.0-dev] — M10 jemmet integration + end-to-end HTTPS acceptance — 2026-06-11

Eleventh implementation milestone (RFC 015), closing the v0.x acceptance target.
jemmet consumes kroopt through one uniform connection abstraction, and a full
HTTPS request is served end-to-end through the modeled stack.

### Added — integration surface (`Kroopt.Conn.Uniform`)

- `PlainConn` — the uniform connection abstraction jemmet depends on
  (`recv`/`send`/`flush`/`close`/`negotiatedProtocol`/`isConnected`). `TlsConn`
  implements it as exactly its public API; `PlainIotaktConn` is the plaintext
  (`:80`) adapter. One jemmet handler path serves both.
- `TlsErrorView` + `redactError` — the typed, redacted failure view jemmet may
  log (category, alert, config generation, SNI *length*); no field for secrets,
  plaintext, or raw attacker bytes by construction.
- `Metrics` — bounded, non-secret operational counters (handshake success/failure,
  alerts, ALPN selections, resource-budget failures).

### Changed

- `TlsConn.recv` is now self-driving: when nothing is buffered it pulls and
  decrypts one record from the transport before retrying, so a single `recv`
  reads the next record off the wire — matching the plaintext adapter and the
  uniform `PlainConn` contract.

### Added — acceptance tests

- `Tests/E2EHttps.lean` (`kroopt-https-test`) — 12 checks: an HTTPS request
  served end-to-end through `TlsConn` (handshake → app-data record → jemmet
  handler → response on the wire); the **same** handler serving a plaintext
  connection; ALPN handoff; plaintext/garbage on the TLS listener never reaching
  the handler as application bytes; no plaintext before `connected`; redacted
  error views; metrics.

### Notes

- No new core theorems: M10 is interop/E2E, classed TESTED. Real iotakt sockets
  and curl/OpenSSL/browser interop are the deferred v0.3 binding — the
  action-mapping is identical, so the real adapter adds no protocol logic.

## [0.10.0-dev] — M9 alerts, close_notify, and terminal policy — 2026-06-11

Tenth implementation milestone (RFC 013). Makes alert mapping and close behaviour
explicit and proved: a single centralized alert mapping, explicit per-mode close
states, truncation distinguished from clean close, and terminal discipline
proved.

### Added — centralized alert mapping (`Kroopt.Core.Alert`, pure)

- `alertForProtocolError`, `alertForParseError`, `alertForCryptoFailure`,
  `alertLevel` — the single deterministic mapping from error class to alert.
  Internal/secret-bearing crypto failures map to no detailed alert; adversarial
  ones map to `bad_record_mac`. Record-layer parse failures now route through this
  mapping rather than hardcoding `decode_error`.

### Changed — explicit per-mode close (RFC 013 §3, §5, §7)

- `step`'s `appClose` distinguishes **graceful** (`closing`/`sentCloseNotify`),
  **fatal** (`failed`/`fatalSent`, emits the alert as the only post-failure
  write), and **abortive** (`closed`/`transportClosed`, no alert). Repeated close
  is idempotent. Transport EOF before close_notify remains a truncation failure,
  never a clean close.

### Added — proofs (`Kroopt.Proofs.Closure`, 7 theorems)

- `failAlert_no_emit`, `failAlert_no_accept`, `failAlert_only_alert_write`
  (the fatal path's only wire effect is its alert), `appClose_no_emit`,
  `alertForParseError_is_fatal`, `alertForParseError_not_closeNotify`,
  `alertForProtocolError_fatal_unless_close`. The three alert-mapping facts use no
  axioms at all. The M0 action-discipline proofs were updated for the refined
  `appClose` and still hold. ~52 total.

### Added — tests

- `Tests/Close.lean` (`kroopt-close-test`) — 16 checks: graceful/fatal/abortive
  close, EOF truncation, inbound close_notify, post-terminal idempotence
  (`appClose`/`appSend`), no buffered plaintext after fatal close, the alert
  mapping, and `TlsConn.close` idempotence through the public API.

## [0.9.0-dev] — M8 SNI/ALPN configuration + server certificate presentation — 2026-06-11

Ninth implementation milestone (RFC 011 / 012). Replaces the hardcoded suite
selection with a real, immutable, validated server-configuration model: an
SNI→endpoint table, ALPN negotiation, and certificate presentation with config
lint — all as pure, deterministic, **proved** functions, then wired into the
live handshake.

### Added — configuration model (`Kroopt.Core.Config`, `Kroopt.Core.Cert`, pure)

- `ServerConfig` / `ValidatedServerConfig` with `validateServerConfig` — a total,
  deterministic validator that stamps a `ConfigGeneration`, rejects ambiguous SNI
  routes, and lints every endpoint's cert/key/suites. Immutable; reload produces a
  new generation (RFC 011 §6).
- `selectEndpoint` — deterministic SNI resolution: exact preferred over wildcard
  (single leftmost label), default fallback, no callbacks (RFC 011 §4, §8).
- `negotiateAlpn` — client/endpoint intersection by policy
  (server-/client-preference, require-overlap).
- `Cert`: `CertificateChainHandle` (opaque DER + minimal leaf metadata),
  `PrivateKeyHandle` (behind a secret handle), `validateEndpointCertKey` (config
  lint), `selectSignatureScheme` (CertificateVerify scheme selection).

### Added — proofs (`Kroopt.Proofs.Config`, 7 theorems, propext-only)

- `negotiateAlpn_offered_and_allowed` — **ALPN safety**: a negotiated protocol is
  always in both the client and endpoint lists; kroopt never selects an unoffered
  protocol (RFC 011 §8).
- `selectEndpoint_none_uses_default`, `validateServerConfig_rejects_ambiguous`,
  `validateServerConfig_preserves_generation`, `selectSignatureScheme_sound`
  (no scheme downgrade), `validateEndpointCertKey_rejects_mismatch`. ~45 total.

### Changed — handshake wiring (additive)

- `NegotiationState` gains `selectedSni` / `selectedAlpn` / `selectedCert`; `State`
  carries an immutable `serverConfig`; `onClientHello` records the SNI/ALPN/cert
  selection. Additive only — all M0–M7 theorems hold unchanged.
- `TlsConn.server` accepts a `ValidatedServerConfig`; `TlsConn.negotiatedAlpn` and
  `selectedCert` accessors added.

### Added — tests

- `Tests/Config.lean` (`kroopt-config-test`) — 17 checks: exact/wildcard SNI,
  default fallback, ALPN intersection by policy and no-overlap, generation
  stamping, ambiguous-config rejection, cert/key lint (compatible/mismatch/empty/
  oversized), and signature-scheme selection.

## [0.8.0-dev] — M7 TlsConn API + non-blocking interpreter — 2026-06-11

Eighth implementation milestone (RFC 010). Adds the runtime layer: the public
`TlsConn` API and the thin imperative interpreter that executes the core's
`OutputAction`s over the transport and crypto provider and feeds results back as
events. The transport is a pure, deterministic fake for this milestone (the real
iotakt binding is a thin deferred adapter, v0.3); the interpreter and API carry
no protocol logic.

### Added — runtime layer (`Kroopt.Conn`)

- `Conn.Transport` — the transport abstraction (the generic non-blocking
  capabilities kroopt requires: `recv`/`send`/`enableWrite`/`disableWrite`/
  `closeConnection`, a generation-protected `FdKey`) and a pure `FakeTransport`
  with scriptable partial writes and EOF. No TLS-specific transport API.
- `Conn.Interpreter` — `execAction` (dispatches on the `OutputAction` variant
  alone; **does not take the core `State`**, so it structurally cannot make a
  protocol decision), `drainOutbound` (partial-write-safe), and the fuel-bounded
  `driveEvents` loop (never spins on `wouldBlock`).
- `Conn.TlsConn` — `server`/`recv`/`send`/`flush`/`close`/`progress`/`metadata`
  with the mandated semantics: `wrote n` = plaintext ownership (not delivery),
  `wouldBlock` consumes zero, `recv` returns authenticated plaintext only after
  `connected`.

### Added — tests, docs

- `Tests/Conn.lean` (`kroopt-conn-test`) — 13 checks: a **full handshake driven
  through the public `TlsConn` API** to `connected`, the write/flush/read
  semantics, partial-write ordering, `wouldBlock`-consumes-zero, progress-budget
  termination, and stale-crypto-result rejection at the runtime boundary.
- `docs/src/tlsconn-interpreter.md`; theorem-inventory note (M7 is interpreter
  *faithfulness*, classed TESTED — the proved guarantees stay in force because the
  interpreter cannot branch on protocol state).

## [0.7.0-dev] — M6 crypto provider, FFI contract, operation-id correlation — 2026-06-11

Seventh implementation milestone (RFC 008 / 009). Adds the crypto provider
trusted boundary and — the verification-first contribution — the **operation-id
correlation guard** on returning crypto results. The native HACL\*/EverCrypt shim
is contracted with its build deferred until HACL\* is vendored (Requirements Open
Question 1); the deterministic fake provider stands in, and the correlation
guarantee holds regardless of provider.

### Added — crypto provider model (`Kroopt.Crypto.Provider`, RFC 008)

- `CryptoCapabilities`, `RequiredCrypto`, `CapabilityError`, and
  `validateCapabilities` — a total, deterministic config-time check that the
  configured suites/groups/signature schemes/hashes are supported and a usable
  random source exists. Capability mismatch is a configuration error, never a
  silent downgrade.
- `CryptoProvider` (synchronous interface) and `fakeProvider` — a deterministic,
  purpose-aware fake satisfying the same interface the real shim will.

### Added — operation-id correlation (the headline)

- `handleCryptoResult` now checks `pendingOps.contains op` before processing a
  result; a stale / duplicate / forged operation id is dropped with no effect.
- `Kroopt.Core.Proofs.stale_crypto_result_rejected` — a non-outstanding op id
  leaves the state unchanged and emits no actions; `stale_crypto_result_no_plaintext`
  is the no-plaintext corollary. Both `propext`-only.
- All M2–M5 safety theorems re-checked over the guarded handler;
  `aead_open_failure_no_plaintext` now carries an explicit "operation outstanding"
  hypothesis (a stale failure is dropped instead).

### Added — native FFI contract (RFC 009), tests, docs

- `Kroopt/Native/kroopt.h` — the C shim contract (one function per primitive /
  secret-handle op, explicit lengths, status codes, documented ownership);
  `kroopt_hacl_shim.c` a documented placeholder pending the HACL\* build.
- `Tests/Crypto.lean` (`kroopt-crypto-test`) — 11 checks: capability validation
  (incl. rejection and no-entropy), the deterministic fake provider, and a
  runtime cross-check of the correlation guard (outstanding processed, stale
  dropped, duplicate is a no-op).
- `docs/src/crypto-ffi-contract.md`; theorem inventory and proof-assumptions
  updated. ~38 theorems total.

## [0.6.0-dev] — M5 live handshake through `step`, fakes, end-to-end — 2026-06-11

Sixth implementation milestone (RFC 014). Wires the M4 handshake transition
functions into the live `step` dispatcher and drives the **full synthetic
handshake end-to-end through `step`** against a fake transport and a
deterministic fake crypto provider. This closes the v0.1 synthetic-core line
(M1–M5): the protocol now runs as it will in production, with only the provider
and sockets faked. Still no real cryptography.

### Added — ClientHello parser (`Kroopt.Parse.Handshake`, RFC 006 §5)

- `parseClientHello` validates a ClientHello on the bounds-safe `Reader`
  primitives (reusing the proved `takeCountedItems`): handshake header, the
  legacy fields, cipher suites, and extensions, requiring TLS 1.3 in
  `supported_versions`, an X25519 `key_share`, an acceptable cipher suite, and no
  duplicate extensions. Returns a `WireBound` carrying the exact consumed bytes.

### Changed — handshake wired into the live handlers

- A plaintext handshake record now routes through `handshakeOnPlaintextRecord`
  (ClientHello in `start`, client Finished in `sentServerFinished`); a gating
  crypto result routes through `handshakeOnGatingResult` (ECDHE / signature /
  verify). `step` and its proof keep their shape — dispatch lives in the record
  handlers (`Kroopt.Core.RecordPath`).

### Added — proofs (the headline: safety survives the live handshake)

- `handshakeOnPlaintextRecord_no_emit` / `_no_accept` / `_no_aeadOpen`,
  `handshakeOnGatingResult_no_emit` / `_no_accept`, and the per-transition
  no-emit/no-accept/no-aeadOpen family.
- Every M2/M3 safety theorem re-checked unchanged over the live handshake:
  `no_plaintext_emit_unless_connected`, `accept_plaintext_only_connected`,
  `buffered_plaintext_authenticated`, `aead_open_failure_no_plaintext`,
  `aeadOpen_uses_read_keys`, `successful_open_increments_read_seq` — all still
  `sorry`/`axiom`-free (`propext`, some `Quot.sound`). ~36 theorems total.

### Added — fakes, end-to-end harness, fuzz

- `Tests/EndToEnd.lean` (`kroopt-e2e-test`) — a deterministic fake crypto
  provider and fake transport, a driver loop over `step`, and 12 checks: a real
  ClientHello byte sequence driven to `connected` with completion reported and no
  plaintext emitted, plus negative traces (malformed ClientHello, early
  application data, bad client Finished) that fail cleanly with no plaintext.
- `Tests/Fuzz.lean` extended with ClientHello and record-reassembly targets
  (RFC 014 §7); buffers widened to 0–255 bytes.

### Added — docs

- `docs/src/end-to-end.md`; expanded theorem inventory and proof-assumptions
  (incl. a note on the fake provider and the synthetic `verifyFailed →
  bad_record_mac` alert-code detail).

## [0.5.0-dev] — M4 handshake state model + transcript binding — 2026-06-11

Fifth implementation milestone (RFC 006 + RFC 007). Adds the TLS 1.3 **server**
handshake state machine (no HelloRetryRequest) and the **exact-wire-byte**
transcript, with the legal-transition and exact-byte-binding proofs. Still no
real crypto and no sockets: the synthetic handshake drives the transition
functions directly with fake crypto results.

### Added — transcript model (`Kroopt.Core.Transcript`, RFC 007)

- `WireBound` binds a parsed value to its exact consumed bytes; `appendParsed`
  commits those bytes, never a reconstruction.
- `HandshakeMessageType`, `TranscriptEvent`/`TranscriptEventMeta`,
  `appendFramed`/`appendParsed`, `snapshot`, `TranscriptSnapshot`,
  `TranscriptBoundInput` + `makeCertificateVerifyInput`/`makeFinishedInput`.

### Added — handshake state model (`Kroopt.Core.Handshake`, RFC 006)

- `ValidClientHello`; `legalEdge` (the allowed phase graph); `installEpoch`;
  `hsFail`; and the five transition functions `onClientHello`, `onEcdheDone`,
  `onCertVerifySigned`, `onClientFinishedBytes`, `onClientFinishedVerified`,
  driving `start → … → connected` via gating crypto actions.

### Added — proofs (`Kroopt.Proofs.Handshake`, `Kroopt.Proofs.Transcript`)

- `onClientHello_legal` … `onClientFinishedVerified_legal` — every transition
  moves along a `legalEdge` (no skipped/out-of-order phases).
- `connected_requires_finished_verified` — `connected` is reachable only from
  `requestedClientFinishedVerify` and only when the client Finished verified.
- `appendFramed_binds_exact_bytes`, `appendParsed_uses_wire_bytes` — exact-byte
  binding; `appendFramed_preserves_order`, `appendFramed_increments_count` —
  ordering; `snapshot_eventCount`, `snapshot_then_append_is_before` — the
  snapshot-before-append discipline for Finished/CertificateVerify.
- `takeCountedItems_bounds` — the fuel-bounded item combinator is bounds-safe
  (composition lemma deferred from M1, now discharged).
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (two on no axioms).

### Added — tests, docs

- `Tests/Handshake.lean` (`kroopt-handshake-test`) — 10 checks: the full
  synthetic handshake to `connected`, the legal phase order, completion
  reporting, the seven-message transcript in order, exact ClientHello byte
  binding, and negative traces (out-of-order ECDHE, bad Finished, duplicate
  ClientHello).
- `docs/src/handshake.md`, `docs/src/transcript.md`; expanded theorem inventory
  and proof-assumptions.

### Changed

- `Core.Transcript` rewritten from the M0 stub to the full RFC 007 model. The
  gates now cover the handshake and transcript modules and their proofs (25
  pure-zone files).

## [0.4.0-dev] — M3 nonce, sequence, epoch, key separation — 2026-06-11

Fourth implementation milestone (RFC 005). Proves the record layer's
cryptographic discipline — the part where a kroopt bug, not a HACL\* bug, would
destroy security: AEAD nonce reuse, sequence wrap, or read/write/epoch key
confusion. Built over the M2 record path; still no real crypto and no sockets.

### Added — nonce / key-epoch model (`Kroopt.Core.Nonce`)

- `KeyEpochId` — a non-secret key-epoch identity (conn, direction, epoch,
  generation) for correlating nonces, proofs, and logs without secret bytes.
- `RecordNonce` / `deriveNonce` — the nonce modeled as the public IV-base
  identity plus the sequence value (the data the uniqueness argument needs).
- `seqBytesBE`, `paddedSeqBytes`, `nonceBytes` — the concrete
  `iv_base XOR left_pad(seq)` byte realization for the interpreter and KATs.

### Added — proofs (`Kroopt.Proofs.Nonces`, `Kroopt.Proofs.KeySeparation`)

- `SeqNo.next_some_succ` / `next_none_overflow` — increment is exactly `+1`;
  `none` only at the `UInt64` ceiling (no wrapped value is produced).
- `successful_seal_increments_write_seq` / `successful_open_increments_read_seq`
  — an accepted seal/open advances that direction's sequence by exactly one.
- `no_crypto_on_write_seq_overflow` — **no silent wrap**: at the ceiling a send
  requests no crypto and fails.
- `nonce_unique_within_epoch` — distinct sequences derive distinct nonces for a
  fixed IV base (depends on no axioms at all).
- `aeadSeal_uses_write_keys` / `aeadOpen_uses_read_keys` — directional and epoch
  key separation: seal ops carry write/application metadata, open ops carry
  read/application metadata.
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (one theorem none, one also `Quot.sound`).

### Added — tests, docs

- `Tests/Nonce.lean` (`kroopt-nonce-test`) — 12 checks: sequence increment and
  ceiling overflow, nonce uniqueness (modeled and concrete bytes), the
  direction/epoch metadata on emitted seal/open ops, and stale/early
  crypto-result behaviour; all passing.
- `docs/src/nonce-sequence.md`; expanded theorem inventory and proof-assumptions.

### Changed

- `Core.Record` gained the `SeqNo.next` increment/overflow lemmas. The gates now
  cover the nonce model and its proofs (22 pure-zone files).

## [0.3.0-dev] — M2 TLS 1.3 record model — 2026-06-11

Third implementation milestone (RFC 004). Adds the TLS 1.3 record model — the
outer/inner content-type distinction, the read/write record paths as core
actions, and the *no unauthenticated plaintext* proof — on top of the M0 core and
M1 parser. Still no real crypto and no sockets: AEAD seal/open are *requested* by
the core and their results fed back as events, exactly as the interpreter will
later drive them.

### Added — record model (`Kroopt.Core.Record`, `Kroopt.Parse.Record`)

- `ContentType` with wire-byte `toByte`/`ofByte` (unknown bytes decode to the
  explicit `invalid`, never a real type).
- `BoundedBytes max` — a byte string whose length bound is a field, so an
  over-length record body is unconstructable; record size limits are enforced
  *by construction*.
- `TLSPlaintext` / `TLSInnerPlaintext` / `TLSCiphertext` — the three record
  shapes keeping the outer `application_data` vs real inner content type
  distinct.
- Record framing: `takeRecordHeader` (rejects oversize length at the header,
  before allocation), `tryTakeRecord` (returns "need more" until a full record is
  buffered — reassembly), `parseInnerPlaintext` (strip padding, read inner type;
  safe list ops, no unchecked indexing), and `classifyCcs` (accept only the
  `0x01` compatibility CCS).

### Added — record path (`Kroopt.Core.RecordPath`, wired into `step`)

- Inbound: reassemble → frame → request `aeadOpen` → on success validate inner
  type and buffer application content → deliver via the existing connected
  `recv` path; auth failure is fatal with no plaintext.
- Outbound: connected `send` fragments to ≤ 2¹⁴, requests `aeadSeal`, and
  acknowledges ownership with `acceptPlaintextBytes`.
- Sequence numbers advance per direction with overflow checked before use; the
  core requests crypto and never calls it.

### Added — proofs (`Kroopt.Proofs.RecordPath`)

- `buffered_plaintext_authenticated` / `buffered_plaintext_provenance` — **no
  unauthenticated plaintext**: buffered application plaintext arises only from a
  successful `aeadOpened` result in `connected` state.
- `aead_open_failure_no_plaintext` — open failure emits no plaintext and is
  terminal.
- Handler no-emit / no-accept lemmas; the M0 `no_plaintext_emit_unless_connected`
  re-proved over the extended `step`, plus `accept_plaintext_only_connected`.
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (some also `Quot.sound`).

### Added — tests, docs

- `Tests/Record.lean` (`kroopt-record-test`) — 19 checks: header parse, oversize
  reject, reassembly split points, inner-type validation, CCS accept/reject, and
  fake AEAD-open success (buffers plaintext) vs failure (buffers none, goes
  terminal); all passing.
- `docs/src/record-model.md`; expanded theorem inventory and proof-assumptions.

### Changed

- `Core.State` gained record buffers (`inboundCiphertext`, `outboundCiphertext`)
  and an op-id counter; `step`'s M0 placeholder arms became real record
  transitions. The proof-hygiene and dependency gates now cover the record
  modules (19 pure-zone files).

## [0.2.0-dev] — M1 bounds-safe parser foundation — 2026-06-11

Second implementation milestone (RFC 003). Adds the pure parsing/framing
foundation with bounds-safety proofs, on top of the M0 core. Still no crypto and
no sockets. (Per the roadmap, the released `v0.1` "synthetic handshake and record
core" line is reached once M1–M5 all land; these `0.x.0-dev` tags are internal
per-milestone snapshots.)

### Added — parser foundation (`Kroopt.Parse`)

- `Reader` — a byte cursor carrying its own `offset ≤ input.size` proof, so
  out-of-bounds readers are unconstructable (*bounds-safety by construction*).
- `UInt24` — a dedicated 24-bit wrapper for handshake lengths (RFC 003 §9.2), in
  place of an unchecked `UInt32` cast.
- Primitives — `takeBytes`, `takeU8`/`U16`/`U24`/`U32` (big-endian), `takeLen`
  (8/16/24-bit prefixes), `remaining`, `atEnd`, `expectEnd`.
- `takeVectorBytes` — length-prefixed byte vector with a `maxLen` budget check
  plus the remaining-input check; the framer the record/extension parsers build
  on.
- `takeCountedItems` — fuel-bounded item combinator (no unbounded recursion over
  attacker-controlled counts).
- `ParseError` — internal typed parse errors with positions/sizes but no raw
  bytes, plus `toPublic` projecting onto the redacted `Kroopt.ParseError`.

### Added — proofs (`Kroopt.Parse.Proofs`, module `Kroopt.Proofs.ParserBounds`)

- `reader_in_bounds`, `takeBytes_bounds`/`_mono`, `takeU8`/`U16`/`U24`/`U32_bounds`,
  `takeLen_bounds`, `takeVectorBytes_bounds`, and the umbrella `parser_bounds_safe`
  — every successful read advances the cursor monotonically, stays within the
  buffer, and preserves the buffer. All machine-checked, no `sorry`/`axiom`/
  `unsafe`; verified via `#print axioms` to depend only on `propext` (some also
  `Quot.sound`).

### Added — tests, fuzzing, docs

- `Tests/Parse.lean` (`kroopt-parse-test`) — 18 unit + negative checks (decode,
  truncation, over-budget length, trailing bytes, fuel exhaustion); all passing.
- `Tests/Fuzz.lean` (`kroopt-parse-fuzz`) — deterministic bounded smoke fuzzer
  asserting the reader invariant across pseudo-random buffers (50k iterations,
  zero violations).
- `docs/src/parser.md` and an expanded theorem inventory / proof-assumptions
  register.

### Changed

- The proof-hygiene and module-dependency gates now cover `Kroopt/Parse`.
- `Kroopt.Parse` depends only on `Kroopt.Error`, keeping it a pure sibling of the
  core (enforced by `scripts/check-deps.sh`).

## [0.1.0-dev] — M0 verified-core skeleton — 2026-06-11

First implementation milestone (RFC 001, 002, 022, 024). Establishes the
pure-core/interpreter architecture with machine-checked safety properties, ahead
of any real crypto or sockets.

### Added — verified core (`Kroopt.Core`)

- `Error` — typed, redaction-safe error and alert taxonomy (all enums; no
  secret-bearing fields), with a coarse `TlsError.category` for logging.
- `Id` — `ConnId` (value + generation), `OperationId`, `ConfigGeneration`.
- `Common` — `CloseMode`, `TimeoutKind`.
- `CipherSuite` — `HashAlgorithm`, `CipherSuite` (+ bound hash), `NamedGroup`,
  `SignatureScheme`.
- `Record` — `Direction`, `Epoch`, `SeqNo` with an overflow-checked `next` that
  returns `none` at the maximum (no silent wrap; RFC 005 §7.2), `EpochState`.
- `Crypto` — crypto-as-action shapes: non-printable `SecretKeyHandle`,
  `RecordCryptoMeta`, `CryptoOpKind`, `CryptoOp`/`CryptoResult`, and the
  pending-op correlation table. Secret-bearing types derive no
  `Repr`/`BEq`/`Hashable` (RFC 018 §3.5).
- `Transcript` — `TranscriptDigestHandle`, `TranscriptState` (minimal M0 shape).
- `State` — `HandshakeState` (16 phases incl. `failed`), `CloseState`,
  `NegotiationState`, `BudgetState`, and the single authoritative `State` with
  `initial` and a redacted diagnostic summary. `State` derives no `Repr`
  (transiently holds authenticated plaintext).
- `Event` / `Action` — `InputEvent` and `OutputAction`, with the classifier
  predicates the proofs quantify over (`isPlaintextEmit`, etc.).
- `Step` — the `step : State → InputEvent → Except TlsError (State × List
  OutputAction)` transition function (M0 shape: correct discipline, no real TLS
  logic yet).

### Added — proofs (`Kroopt.Proofs`)

- `step_deterministic`, `terminal_absorbing`, `terminal_no_error`,
  `no_plaintext_emit_unless_connected` (*no early plaintext*), and
  `no_plaintext_after_terminal`. All machine-checked, no `sorry`/`axiom`/
  `unsafe`; verified via `#print axioms` to depend only on `propext`.

### Added — tests, gates, docs

- `Tests/Model.lean` — deterministic model test driving `step` directly (9
  checks, all passing).
- `scripts/check-hygiene.sh` — RFC 022 proof-hygiene gate (no forbidden
  constructs in the strict zones).
- `scripts/check-deps.sh` — RFC 022 module-dependency gate (verified core may
  not import the interpreter, crypto provider, native shim, or iotakt).
- `docs/src/` — mdbook docs: introduction, boundary, theorem inventory, and the
  proof-assumptions register.

### Project

- Incorporated the ROADMAP and full RFC set (managed under the lifecycle policy)
  into the repository. RFCs remain `Proposed`; their M0 slices are implemented
  but the RFCs are not yet fully realized, so they stay in `rfcs/proposed/`.
- Lake package builds standalone on a clean Lean install — no mathlib, no C
  toolchain, no network reactor (RFC 024 `core` profile).
