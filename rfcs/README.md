# kroopt RFC Index

RFCs are managed according to the [RFC lifecycle policy](done/000-rfc-lifecycle-policy.md).
The folder is the source of truth for each RFC's state; the `**Status.**` field
inside each file mirrors its folder.

- `proposed/` — open for review / not yet fully shipped.
- `done/` — implemented; `**Status.** Implemented (vX.Y.Z)`, folder is authoritative.
- `archive/` — withdrawn or superseded, with a one-line reason.

The implementation RFCs (001–030) were audited against their own acceptance
criteria at **0.24.0-dev**; those whose criteria are fully met were migrated to
`done/`. The ten that remain in `proposed/` each have a specific named
deliverable still open (listed below), concentrated in the v0.3 real-interop and
v0.4 hardening / release-governance bands.

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
control), then 017–030 (cross-cutting security, lifecycle, and release governance).

## Proposed — open deliverable remaining

| ID | Title | Pending before `done/` |
|----|-------|------------------------|
| 009 | [HACL*/EverCrypt Shim, KATs, and Sanitizer Strategy](proposed/009-hacl-evercrypt-shim-kat-sanitizer.md) | ASan/UBSan sanitizer CI job (shim + KATs done) |
| 015 | [jemmet Integration and End-to-End Acceptance](proposed/015-jemmet-integration-and-e2e-acceptance.md) | Real OpenSSL/curl handshake + jemmet HTTPS E2E over the wire |
| 024 | [Native Build, Lake Packaging, and Feature Gates](proposed/024-native-build-lake-packaging-and-features.md) | Sanitizer build profile in CI (pure + native profiles done) |
| 025 | [Performance and Memory Benchmark Policy](proposed/025-performance-and-memory-benchmark-policy.md) | Parser/record microbenchmarks + loopback throughput |
| 026 | [Compatibility, Interop, and Negative Matrix](proposed/026-compatibility-interop-and-negative-matrix.md) | Positive OpenSSL/curl/browser interop matrix (negatives done) |
| 027 | [Public API Stability and Versioning](proposed/027-public-api-stability-and-versioning.md) | Public API stability commitment (post-v0.3 / pre-1.0) |
| 029 | [Developer Documentation and Examples](proposed/029-developer-documentation-and-examples.md) | Tested/compile-checked API + progress-loop examples |
| 030 | [Production Readiness and Release Runbook](proposed/030-production-readiness-and-release-runbook.md) | `docs/src/release-runbook.md` + release checklist |
| 035 | [Browser-Grade Crypto Surface](proposed/035-browser-grade-crypto-surface.md) | Deferred — AES-GCM/P-256/ECDSA/RSA + cert-ecosystem story only after M36/M37/M38 green |
| 037 | [Native FFI Safety, Secret Arena, and Resource-Budget Enforcement](proposed/037-native-safety-and-budget-enforcement.md) | FFI length contracts (all `uint32_t` params); native/classified secret arena; budget charging in the core; record-size guards; sanitizers (M37) |
| 040 | [Native Traffic-Secret Arena and the IO Production Interpreter](proposed/040-native-traffic-secret-arena.md) | **Blocked on RFC 031.** Stable/v1 gate — migrate connection traffic secrets onto the C-owned zeroizing arena via a two-interpreter (pure model + IO production) architecture; records the D-now/A-later decision |

## Done

All acceptance criteria met; migrated to `done/` at 0.24.0-dev. "Shipped in" is the
milestone where the work substantively landed (see CHANGELOG/ROADMAP for detail).

| ID | Title | Shipped in |
|----|-------|------------|
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

## Current state — constrained-profile edge band (post-0.48.0-dev)

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
- HTTP/1.1 keep-alive over the kroopt + iotakt edge.

No RFC moved to `done/` in this band: each candidate has a logged deferral by its own acceptance —
RFC 010 (real iotakt adapter), RFC 031 (async-crypto runtime ledger), RFC 037 (C zeroizing arena).
The AES-GCM / SHA-384 crypto breadth (RFC 035) and browser interop (RFC 026) remain blocked on the
available HACL\* source and the test host respectively, and gate a non-dev v0.4.0.

## Archive

_None yet. RFCs move here when withdrawn or superseded._
