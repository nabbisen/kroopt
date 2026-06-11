# kroopt RFC Index

RFCs are managed according to the [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md).
The folder is the source of truth for each RFC's state; the `**Status.**`
field inside each file mirrors its folder.

- `proposed/` — open for review (all kroopt RFCs are here; none implemented yet).
- `done/` — implemented; moved here with `**Status.** Implemented (vX.Y.Z)`.
- `archive/` — withdrawn or superseded, with a one-line reason.

Read order: ROADMAP first, then RFCs 001–007 (pure verified core), 008–009
(crypto integration), 010–015 (runtime integration and acceptance), 016 (scope
control), then 017–030 (cross-cutting security, lifecycle, and release governance).

## Proposed — Wave 1: implementation architecture (RFC 001–016)

| ID | Title | Target milestone |
|----|-------|------------------|
| 001 | [Boundary and Non-Goals](proposed/001-boundary-and-non-goals.md) | M0 |
| 002 | [Verified Core and Proof/Runtime Correspondence](proposed/002-verified-core-and-proof-runtime-correspondence.md) | M0 |
| 003 | [Bounds-Safe Parser and Framer Foundation](proposed/003-bounds-safe-parser-and-framer.md) | M1 |
| 004 | [TLS 1.3 Record Model](proposed/004-tls13-record-model.md) | M2 |
| 005 | [Nonce, Sequence, Epoch, and Key-Separation Proofs](proposed/005-nonce-sequence-epoch-key-separation-proofs.md) | M3 |
| 006 | [Handshake State Model without HelloRetryRequest](proposed/006-handshake-state-model-no-hrr.md) | M4 |
| 007 | [Transcript Model Using Exact Wire Bytes](proposed/007-transcript-model-exact-wire-bytes.md) | M4 |
| 008 | [Crypto Provider Capability Matrix and FFI Contract](proposed/008-crypto-provider-capability-and-ffi-contract.md) | M6 |
| 009 | [HACL*/EverCrypt Shim, Known-Answer Tests, and Sanitizer Strategy](proposed/009-hacl-evercrypt-shim-kat-sanitizer.md) | M6 |
| 010 | [TlsConn API and Non-Blocking iotakt Interpreter](proposed/010-tlsconn-api-nonblocking-interpreter.md) | M7 |
| 011 | [SNI/ALPN Configuration Model](proposed/011-sni-alpn-configuration-model.md) | M8 |
| 012 | [Server Certificate/Key Presentation](proposed/012-server-certificate-key-presentation.md) | M8 |
| 013 | [Alerts, close_notify, and Terminal Policy](proposed/013-alerts-close-and-terminal-policy.md) | M9 |
| 014 | [Deterministic Test Harness, Fake Crypto, Fake Transport, and Fuzzing](proposed/014-test-harness-fuzzing-and-determinism.md) | M5 |
| 015 | [jemmet Integration and End-to-End Acceptance](proposed/015-jemmet-integration-and-e2e-acceptance.md) | M10 |
| 016 | [Deferred Future TLS Features and Scope Control](proposed/016-deferred-future-tls-features.md) | Future |

## Proposed — Wave 2: cross-cutting controls (RFC 017–030)

| ID | Title | Earliest active / deadline |
|----|-------|----------------------------|
| 017 | [Threat Model and Abuse Cases](proposed/017-threat-model-and-abuse-cases.md) | Cross-cutting (M0; current before v0.3) |
| 018 | [Data Classification and Lifecycle](proposed/018-data-classification-and-lifecycle.md) | M0–v0.2 |
| 019 | [Resource Budgets, Backpressure, and DoS Defense](proposed/019-resource-budgets-backpressure-and-dos-defense.md) | v0.1 (fake); v0.3 (network) |
| 020 | [Observability, Audit Logging, and Redaction](proposed/020-observability-audit-logging-and-redaction.md) | v0.3; v0.4 |
| 021 | [Configuration Lifecycle and Reload](proposed/021-configuration-lifecycle-and-reload.md) | v0.3 (snapshots); v0.4 (reload) |
| 022 | [Proof Gates, CI, and Lean Hygiene](proposed/022-proof-gates-ci-and-lean-hygiene.md) | M0 onward |
| 023 | [Parser Fuzzing, Corpus, and Mutation Policy](proposed/023-parser-fuzzing-corpus-and-mutation-policy.md) | v0.1; mandatory before v0.4 |
| 024 | [Native Build, Lake Packaging, and Feature Gates](proposed/024-native-build-lake-packaging-and-features.md) | M0 (skeleton); v0.2 (native) |
| 025 | [Performance and Memory Benchmark Policy](proposed/025-performance-and-memory-benchmark-policy.md) | v0.3 onward; micro earlier |
| 026 | [Compatibility, Interop, and Negative Matrix](proposed/026-compatibility-interop-and-negative-matrix.md) | v0.3; v0.4 |
| 027 | [Public API Stability and Versioning](proposed/027-public-api-stability-and-versioning.md) | M0; commitment v0.3/v0.4 |
| 028 | [Security Review and Vulnerability Process](proposed/028-security-review-and-vulnerability-process.md) | Before v0.3 exposure |
| 029 | [Developer Documentation and Examples](proposed/029-developer-documentation-and-examples.md) | v0.3; v0.4 |
| 030 | [Production Readiness and Release Runbook](proposed/030-production-readiness-and-release-runbook.md) | v0.4 and every release after |

## Done

| ID | Title | Status |
|----|-------|--------|
| 000 | [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md) | Implemented |

_No kroopt implementation RFCs are done yet. RFCs 001–030 move here when their work ships._

## Archive

_None yet. RFCs move here when withdrawn or superseded._
