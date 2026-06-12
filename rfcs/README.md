# kroopt RFC Index

RFCs are managed according to the [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md).
The folder is the source of truth for each RFC's state; the `**Status.**` field
inside each file mirrors its folder.

- `proposed/` — open for review / not yet fully shipped.
- `done/` — implemented; `**Status.** Implemented (vX.Y.Z)`, folder is authoritative.
- `archive/` — withdrawn or superseded, with a one-line reason.

The implementation RFCs (001–030) were audited against their own acceptance
criteria at **0.24.0-dev**; those whose criteria are fully met were migrated to
`done/`. The eleven that remain in `proposed/` each have a specific named
deliverable still open (listed below), concentrated in the v0.3 real-interop and
v0.4 hardening / release-governance bands.

RFCs **031–037** were added after the 0.35.0-dev architecture review and amended after
the review of the RFCs themselves. They form the pre-interop correspondence-and-hardening
band: **034** (M36-prelude) shipped the immediate honesty fix in 0.36.0-dev (real
provider capabilities + fail-closed entropy); **031–033** (M36) close the proof/runtime correspondence gap and
make the production interpreter process real-client handshakes (typed actions, handshake
reassembly, overlap negotiation, protected handshake records before `connected`); **037**
(M37) hardens the native boundary, secret arena, and resource budgets; **036** adds the
captured-client replay + trace harness for **038** constrained OpenSSL/curl interop; and
**035** records the decision to defer browser-grade crypto breadth until the constrained
profile is proven against live clients. iotakt binding (RFC 010) and external interop
(RFC 015/026) are frozen until 031–033 (and, before live clients, 037) land; 034 is done.

Read order: ROADMAP first, then RFCs 001–007 (pure verified core), 008–009
(crypto integration), 010–015 (runtime integration and acceptance), 016 (scope
control), then 017–030 (cross-cutting security, lifecycle, and release governance).

## Proposed — open deliverable remaining

| ID | Title | Pending before `done/` |
|----|-------|------------------------|
| 009 | [HACL*/EverCrypt Shim, KATs, and Sanitizer Strategy](proposed/009-hacl-evercrypt-shim-kat-sanitizer.md) | ASan/UBSan sanitizer CI job (shim + KATs done) |
| 010 | [TlsConn API and Non-Blocking iotakt Interpreter](proposed/010-tlsconn-api-nonblocking-interpreter.md) | Real iotakt socket `Transport` adapter (API/interpreter done over the fake transport) |
| 015 | [jemmet Integration and End-to-End Acceptance](proposed/015-jemmet-integration-and-e2e-acceptance.md) | Real OpenSSL/curl handshake + jemmet HTTPS E2E over the wire |
| 020 | [Observability, Audit Logging, and Redaction](proposed/020-observability-audit-logging-and-redaction.md) | Operator-facing event/metric reference doc (redaction + typed errors done) |
| 024 | [Native Build, Lake Packaging, and Feature Gates](proposed/024-native-build-lake-packaging-and-features.md) | Sanitizer build profile in CI (pure + native profiles done) |
| 025 | [Performance and Memory Benchmark Policy](proposed/025-performance-and-memory-benchmark-policy.md) | Parser/record microbenchmarks + loopback throughput |
| 026 | [Compatibility, Interop, and Negative Matrix](proposed/026-compatibility-interop-and-negative-matrix.md) | Positive OpenSSL/curl/browser interop matrix (negatives done) |
| 027 | [Public API Stability and Versioning](proposed/027-public-api-stability-and-versioning.md) | Public API stability commitment (post-v0.3 / pre-1.0) |
| 028 | [Security Review and Vulnerability Process](proposed/028-security-review-and-vulnerability-process.md) | `SECURITY.md` + release-blocker review checklist |
| 029 | [Developer Documentation and Examples](proposed/029-developer-documentation-and-examples.md) | Tested/compile-checked API + progress-loop examples |
| 030 | [Production Readiness and Release Runbook](proposed/030-production-readiness-and-release-runbook.md) | `docs/src/release-runbook.md` + release checklist |
| 031 | [Production Interpreter Correspondence](proposed/031-production-interpreter-correspondence.md) | Byte-accurate handshake driven by the production interpreter from typed core-authorized actions; op-id lifecycle; correspondence ledger + tests (M36) |
| 032 | [Typed Handshake/Record Assembly Contract](proposed/032-typed-flight-assembly-contract.md) | Typed core handshake/record actions replacing placeholder frames; two-stage crypto actions; handshake-bytes transcript; proofs re-established; CI gate (M36) |
| 033 | [Real-Client Handshake Processing](proposed/033-real-client-handshake-processing.md) | Protected handshake records before `connected`; handshake-message reassembly; overlap-selection negotiation; explicit CCS; ClientHello strictness (M36) |
| 035 | [Browser-Grade Crypto Surface](proposed/035-browser-grade-crypto-surface.md) | Deferred — AES-GCM/P-256/ECDSA/RSA + cert-ecosystem story only after M36/M37/M38 green |
| 036 | [Live Interop Trace Harness and Captured-Client Replay](proposed/036-live-interop-trace-harness.md) | Captured-CH replay fixtures; no-secrets trace facility; constrained-vs-browser-grade separation (M38; prep in M36) |
| 037 | [Native FFI Safety, Secret Arena, and Resource-Budget Enforcement](proposed/037-native-safety-and-budget-enforcement.md) | FFI length contracts (all `uint32_t` params); native/classified secret arena; budget charging in the core; record-size guards; sanitizers (M37) |

## Done

All acceptance criteria met; migrated to `done/` at 0.24.0-dev. "Shipped in" is the
milestone where the work substantively landed (see CHANGELOG/ROADMAP for detail).

| ID | Title | Shipped in |
|----|-------|------------|
| 000 | [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md) | Implemented |
| 034 | [Provider Capability Honesty and Fail-Closed Entropy](done/034-provider-capability-honesty-and-entropy.md) | 0.36.0-dev (M36-prelude) |
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

## Archive

_None yet. RFCs move here when withdrawn or superseded._
