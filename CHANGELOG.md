# Changelog

All notable changes to kroopt are recorded here. RFC lifecycle transitions are
governed by [`rfcs/done/000-rfc-lifecycle-policy.md`](rfcs/done/000-rfc-lifecycle-policy.md).

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
