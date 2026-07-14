# kroopt RFC Index

RFCs are managed according to the [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md).
The folder is the source of truth for each RFC's state; the `**Status.**` field
inside each file mirrors its folder.

- `proposed/` — open for review / not yet fully shipped.
- `done/` — implemented; `**Status.** Implemented (vX.Y.Z)`, folder is authoritative.
- `archive/` — withdrawn or superseded, with a one-line reason.

The implementation RFCs (001–030) were audited against their own acceptance
criteria at **0.24.0-dev**; those whose criteria were then considered met were
migrated to `done/`. The independent architecture review of `0.124.1`
(`b4fcedf166c4b77256d46fd6f509c73ead2a3ad0`, 2026-07-13) supersedes the
handoff's production-ready posture: production/stable adoption is **NO-GO** while
the AR0–AR3 remediation program in [`ROADMAP.md`](../ROADMAP.md#0-architecture-review-remediation-program-2026-07-13)
is open; stable/v1 additionally requires AR4 / RFC 040. Existing `done/` RFCs
remain durable design history, but a new follow-up RFC may reopen an uncovered
acceptance gap without rewriting that history.

RFCs **031–037** were added after the 0.35.0-dev architecture review and amended after
the review of the RFCs themselves. They form the pre-interop correspondence-and-hardening
band: **034** (M36-prelude) shipped the immediate honesty fix in 0.36.0-dev (real
provider capabilities + fail-closed entropy); **033** (M36, done in 0.42.0-dev) made the core process real-client handshakes
(protected handshake records before `connected`, capability-bound overlap negotiation, ClientHello
strictness, explicit CCS window, handshake-message reassembly); **032** (M36, done in 0.46.0-dev)
made every server-flight message a typed core action with the transcript over serialized bytes and a
CI gate against placeholder/first-byte dispatch; **031** (M36) is **locked for synchronous
production-interpreter correspondence** (0.88.0-dev) — byte-accurate production-interpreter
correspondence including the configured Certificate DER, with the async crypto-result ledger and
stale-result refinements relocated to RFC 040; **037**
(M37) hardens the native boundary, secret arena, and resource budgets; **036** adds the
captured-client replay + trace harness for **038** constrained OpenSSL/curl interop; and
**035** records the decision to defer browser-grade crypto breadth until the constrained
profile is proven against live clients. **038** is reserved for that constrained-interop
RFC (not yet written); **039** (implemented at 0.81.0-dev, after the 0.76.0-dev secp256r1
capability-gap review) made the key-exchange-group dimension load-bearing — endpoint group
policy, capability enforcement, core-level selection, and a selection-authorization proof. **040**
(added after 039) records the architect-reviewed decision on the traffic-secret C-arena migration:
connection-lifetime traffic secrets move onto the C-owned zeroizing arena via a two-interpreter
(pure model + IO production) architecture, but this is **blocked on 031** and gated to **stable/v1**
— the pre-stable line keeps documented best-effort traffic-secret zeroization (the server *private
key* is already C-owned). iotakt binding (RFC 010) and external interop
(RFC 015/026) were frozen until 031 locked; with **031 locked for synchronous correspondence
(0.88.0-dev)** the real-wire band is **unfrozen** — RFC 010 (iotakt socket adapter) is **locked
(Implemented, 0.91.0-dev)** with live OpenSSL/Python interop, and RFC 036 (replay + trace harness) is
**locked (Implemented, 0.96.0-dev)** with three-client live interop (OpenSSL/Python/curl) and the
constrained-vs-browser-grade docs; the RFC 037 inbound-alert residue is done, leaving live jemmet
HTTPS E2E + interop breadth (RFC 015/026) the headline track; 031, 032, 033, 034 and 039 are done.

Read order: ROADMAP first, then RFCs 001–007 (pure verified core), 008–009
(crypto integration), 010–015 (runtime integration and acceptance), 016 (scope
control), then 017–030 (cross-cutting security, lifecycle, and release governance),
031–043 (correspondence/native/interop hardening history), and finally 044–054
(the current architecture-review remediation and deferred-evolution schedule).

## Proposed — architecture-review remediation schedule

These RFCs turn every blocking/non-blocking architecture-review theme into a
durable work item. Milestone order and release decision gates are in ROADMAP §0.

| ID | Title | Milestone / purpose |
|----|-------|---------------------|
| 044 | [Async Crypto Offload and Result Correlation](proposed/044-async-crypto-offload-and-result-correlation.md) | Deferred until after AR4; preserves RFC 040's sync-first boundary |
| 045 | [Endpoint Negotiation Policy Authorization](proposed/045-endpoint-negotiation-policy-authorization.md) | AR1 — B1 endpoint cipher policy |
| 046 | [Strict ClientHello and Extension Framing](proposed/046-strict-clienthello-and-extension-framing.md) | AR1 — B2 strict parsing/fuzzing |
| 047 | [Monotonic Deadlines and Timeout Enforcement](proposed/047-monotonic-deadlines-and-timeout-enforcement.md) | AR2 — B3 handshake/idle/close deadlines |
| 048 | [Validated Construction and Protected-Epoch Fail-Closed Behavior](proposed/048-validated-construction-and-protected-epoch-fail-closed.md) | AR1 — B4 construction and protected-flight safety |
| 049 | [Record-Phase Acceptance and Clean-Close Semantics](proposed/049-record-phase-acceptance-and-clean-close.md) | AR1 — B5 plus public graceful EOF |
| 050 | [Bounded Certificate-Chain Presentation](proposed/050-bounded-certificate-chain-presentation.md) | AR2 — B8 real certificate lists |
| 052 | [jemmet+iotakt Production-Path Acceptance](proposed/052-jemmet-iotakt-production-path-acceptance.md) | AR3 — real downstream evidence; coordinates RFC 015/026 |
| 054 | [Maintainability Split and History Archival](proposed/054-maintainability-split-and-history-archival.md) | AR-M — module/history concentration before stable |

## Proposed — pre-existing open deliverables

| ID | Title | Pending before `done/` |
|----|-------|------------------------|
| 009 | [HACL*/EverCrypt Shim, KATs, and Sanitizer Strategy](proposed/009-hacl-evercrypt-shim-kat-sanitizer.md) | ASan/UBSan sanitizer CI job (shim + KATs done) |
| 015 | [jemmet Integration and End-to-End Acceptance](proposed/015-jemmet-integration-and-e2e-acceptance.md) | Real OpenSSL/curl handshake + jemmet HTTPS E2E over the wire |
| 024 | [Native Build, Lake Packaging, and Feature Gates](proposed/024-native-build-lake-packaging-and-features.md) | Sanitizer build profile in CI (pure + native profiles done) |
| 025 | [Performance and Memory Benchmark Policy](proposed/025-performance-and-memory-benchmark-policy.md) | Parser/record microbenchmarks + loopback throughput |
| 026 | [Compatibility, Interop, and Negative Matrix](proposed/026-compatibility-interop-and-negative-matrix.md) | Positive OpenSSL/curl/browser interop matrix (negatives done) |
| 027 | [Public API Stability and Versioning](proposed/027-public-api-stability-and-versioning.md) | Public API stability commitment (post-v0.3 / pre-1.0) |
| 029 | [Developer Documentation and Examples](proposed/029-developer-documentation-and-examples.md) | Tested/compile-checked API + progress-loop examples |
| 035 | [Browser-Grade Crypto Surface](proposed/035-browser-grade-crypto-surface.md) | Deferred — AES-GCM/P-256/ECDSA/RSA + cert-ecosystem story only after M36/M37/M38 green |
| 037 | [Native FFI Safety, Secret Arena, and Resource-Budget Enforcement](proposed/037-native-safety-and-budget-enforcement.md) | FFI length contracts (all `uint32_t` params); native/classified secret arena; budget charging in the core; record-size guards; sanitizers (M37) |
| 040 | [Native Traffic-Secret Arena and the IO Production Interpreter](proposed/040-native-traffic-secret-arena.md) | **Design in progress (0.123.x).** Preconditions met (031 done; 037 arena exists/sanitizer-clean; 013 done) — 040 is the remaining traffic-secret branch of the native-secret arc. Branch: sync-first / staged / proved-core+tested-lift; async sealing is a non-goal (→ future 044). Stable/v1 gate. [Handoff](handoffs/self/040-native-traffic-secret-arena/README.md): internal design + slice plan + Slice 1 acceptance |

## Done

RFCs listed here have met their acceptance criteria and migrated to `done/`. The original implementation-RFC
audit migrated its completed set at 0.24.0-dev; later RFCs moved as their own evidence gates closed. "Shipped
in" identifies where each item substantively landed (see CHANGELOG/ROADMAP for detail).

| ID | Title | Shipped in |
|----|-------|------------|
| 053 | [Project Truth and Security-Claim Reconciliation](done/053-project-truth-and-security-claim-reconciliation.md) | Implemented (AR0, unreleased; `2984db0`) — public/security/release/RFC claims reconciled; pre-production and traffic-secret limitations made explicit |
| 051 | [Release-Gate Portability and Canonical Evidence](done/051-release-gate-portability-and-canonical-evidence.md) | Implemented (AR0, unreleased; `2984db0`) — clean full-release gate 42/42 plus GCC 12.5/16.1 sanitizer lanes in CI run `79277038502` |
| 030 | [Production Readiness and Release Runbook](done/030-production-readiness-and-release-runbook.md) | Implemented (Stage A 0.119.0; Stage B 0.121.0–0.121.1; Stage C 0.122.0; ratified 0.122.1) — canonical `gate.sh` + ledger; reproducible packaging/sidecar/self-verification; immutable tag publishing first exercised by `0.124.0` |
| 043 | [HACL*/EverCrypt Vendoring and Provenance Discipline](done/043-hacl-evercrypt-vendoring-and-provenance.md) | Implemented (0.120.0–0.120.2) — byte-level anchor of the vendored tree to the named upstream `ocaml-v0.4.5` artifact (166 files, 0 mods); per-file manifest outside the hash-covered tree; offline `check-hacl-provenance.sh` gate (tree==manifest) in `gate.sh` + online `verify-hacl-upstream.sh` (manifest==upstream); trust-matrix restored to anchored-inherited. First upstream bump exercises §10, not a done-gate |
| 042 | [Resource-limit Enforcement and Configurability](done/042-resource-limit-enforcement.md) | Implemented (0.115–0.116.0-dev) — validated limits, core charge sites, bounded egress, and closeout cleanup |
| 041 | [Fatal-alert wire transmission](done/041-fatal-alert-wire-transmission.md) | Implemented (0.111–0.114.0-dev) — core `writeAlert` action + `AlertDescription.toByte` round-trip proof; plaintext (initial, live-observed) + sealed (handshake/application) fatal alerts; dual `alertsClassified`/`alertsSent`; record-path `recordFailAlert` wired (0.113); doc/comment closeout (0.114) |
| 000 | [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md) | Implemented |
| 039 | [Named-Group Policy and Selection Enforcement](done/039-named-group-policy-and-enforcement.md) | Implemented (0.81.0-dev) |
| 031 | [Production Interpreter Correspondence](done/031-production-interpreter-correspondence.md) | Implemented (0.88.0-dev) — **synchronous** correspondence locked; async ledger + stale-result refinements relocated to RFC 040 |
| 010 | [TlsConn API and Non-Blocking iotakt Interpreter](done/010-tlsconn-api-nonblocking-interpreter.md) | Implemented (0.91.0-dev) — TlsConn API + non-blocking interpreter + real-socket driver; live OpenSSL/Python interop. Live-interop breadth (026) / jemmet E2E (015) tracked separately |
| 036 | [Live Interop Trace Harness and Captured-Client Replay](done/036-live-interop-trace-harness.md) | Implemented (0.96.0-dev) — deterministic captured-client replay (constrained+broad+malformed) + secret-free `debug_trace` facility + constrained-vs-browser-grade docs (incl. tested GREASE tolerance). Durable live-transcript archival relocated to M38 |
| 020 | [Observability, Audit Logging, and Redaction](done/020-observability-audit-logging-and-redaction.md) | Implemented (0.98.0-dev) — v0.3 lock: trace taxonomy, redaction, coarse public error view, default-off debug trace, operator event/metric reference. Public `SecurityEvent` API + live metric emission/histograms/export relocated to v0.4 |
| 028 | [Security Review and Vulnerability Process](done/028-security-review-and-vulnerability-process.md) | Implemented (0.86.0-dev) |
| 032 | [Typed Handshake/Record Assembly Contract](done/032-typed-flight-assembly-contract.md) | Implemented (0.46.0-dev) |
| 034 | [Provider Capability Honesty and Fail-Closed Entropy](done/034-provider-capability-honesty-and-entropy.md) | 0.36.0-dev (M36-prelude) |
| 033 | [Real-Client Handshake Processing](done/033-real-client-handshake-processing.md) | 0.37–0.42.0-dev (M36 parts 1–6) |
| 001 | [Boundary and Non-Goals](done/001-boundary-and-non-goals.md) | M0 |
| 002 | [Verified Core and Proof/Runtime Correspondence](done/002-verified-core-and-proof-runtime-correspondence.md) | M0 |
| 003 | [Bounds-Safe Parser and Framer Foundation](done/003-bounds-safe-parser-and-framer.md) | M1 |
| 004 | [TLS 1.3 Record Model](done/004-tls13-record-model.md) | M2 |
| 005 | [Nonce, Sequence, Epoch, and Key-Separation Proofs](done/005-nonce-sequence-epoch-key-separation-proofs.md) | M3 |
| 006 | [Handshake State Model without HelloRetryRequest](done/006-handshake-state-model-no-hrr.md) | M4 |
| 007 | [Transcript Model Using Exact Wire Bytes](done/007-transcript-model-exact-wire-bytes.md) | M4 |
| 008 | [Crypto Provider Capability Matrix and FFI Contract](done/008-crypto-provider-capability-and-ffi-contract.md) | M6 |
| 011 | [SNI/ALPN Configuration Model](done/011-sni-alpn-configuration-model.md) | M8 |
| 012 | [Server Certificate/Key Presentation](done/012-server-certificate-key-presentation.md) | M8 |
| 013 | [Alerts, close_notify, and Terminal Policy](done/013-alerts-close-and-terminal-policy.md) | M9 |
| 014 | [Deterministic Test Harness, Fake Crypto, Fake Transport, and Fuzzing](done/014-test-harness-fuzzing-and-determinism.md) | M5 |
| 016 | [Deferred Future TLS Features and Scope Control](done/016-deferred-future-tls-features.md) | M11 (standing policy) |
| 017 | [Threat Model and Abuse Cases](done/017-threat-model-and-abuse-cases.md) | M11 |
| 018 | [Data Classification and Lifecycle](done/018-data-classification-and-lifecycle.md) | M11 |
| 019 | [Resource Budgets, Backpressure, and DoS Defense](done/019-resource-budgets-backpressure-and-dos-defense.md) | M11 |
| 021 | [Configuration Lifecycle and Reload](done/021-configuration-lifecycle-and-reload.md) | M8 |
| 022 | [Proof Gates, CI, and Lean Hygiene](done/022-proof-gates-ci-and-lean-hygiene.md) | M11 |
| 023 | [Parser Fuzzing, Corpus, and Mutation Policy](done/023-parser-fuzzing-corpus-and-mutation-policy.md) | M5 |

_Note: RFC 016 is a standing scope-control policy (deferral decision in effect and
enforced by tests); the deferred TLS features themselves land later via descendant
RFCs, as RFC 016 requires._

## Historical snapshot — constrained-profile edge band (0.48.0-dev–0.65.0-dev)

This section is retained as milestone history and is not the current RFC or readiness state. Use the
[architecture-review remediation schedule](#proposed--architecture-review-remediation-schedule), ROADMAP
§0, and the [current security state](../docs/src/verification/current-security-state.md) for current truth.

After the M37 native-hardening band (0.48.0-dev), work proceeded under RFC 010 (now Implemented at
0.91.0-dev) and the
constrained crypto profile to make the server feature-complete for HTTPS edge serving and validate it
against live clients (OpenSSL/curl). Landed and live-validated through **0.65.0-dev**:

- P-256 ECDHE and the ECDSA-P256 / RSA-PSS server-auth schemes alongside Ed25519 (RFC 012);
- SNI multi-certificate selection — exact and wildcard routes — and per-endpoint ALPN negotiation
  (RFC 011), each fixed from a latent raw-extension-framing parser bug;
- a clean `handshake_failure` on no signature-scheme overlap (PROVEN);
- a cert / private-key compatibility lint across Ed25519, EC P-256, and RSA leaves (RFC 011 §11.2),
  plus config-validation rejection of malformed ALPN identifiers and ambiguous SNI routes;
- HTTP/1.1 keep-alive over the TLS data path (SocketReactor stand-in; the real iotakt adapter is jemmet's node, no kroopt iotakt edge).

At the time of this historical snapshot, no RFC moved to `done/` in this band: each candidate had a logged deferral by its own acceptance —
RFC 010 (standup over jemmet's real iotakt adapter), RFC 031 (async-crypto runtime ledger), RFC 037 (C zeroizing arena).
The AES-GCM / SHA-384 crypto breadth (RFC 035) and browser interop (RFC 026) remain blocked on the
available HACL\* source and the test host respectively, and gate a non-dev v0.4.0.

## Archive

_None yet. RFCs move here when withdrawn or superseded._
