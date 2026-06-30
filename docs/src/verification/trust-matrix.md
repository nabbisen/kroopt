# Trust matrix

The single consolidated claim-by-claim matrix: every property kroopt relies on, in one place, with its
status, the concrete evidence, who owns it, what gap remains, and the release at which the gap must
close. It complements the [current security state](current-security-state.md) (which is the capability
inventory) and supersedes the scattered restatements in other pages where they differ.

**Status vocabulary.** `PROVEN` = machine-checked over `Kroopt.Core.step`; `TESTED` = covered by CI
suites / KAT / fuzz / live interop; `ASSUMED` = inherited from a trusted external component (HACL\*,
OS); `BEST-EFFORT` = attempted but not guaranteed; `NOT CLAIMED` = explicitly out of scope.

**Proof hygiene baseline.** The axiom gate (`scripts/check-axioms.sh`) reports: *109 public theorems
audited, no `sorryAx`, axioms within `{propext, Quot.sound, Classical.choice}`.* All `PROVEN` rows are
within that audited set.

## Core protocol safety — PROVEN over `step`

| Claim | Status | Evidence (theorem / suite) | Owner | Remaining gap | Release gate |
|---|---|---|---|---|---|
| No application plaintext before `connected` | PROVEN | `no_plaintext_emit_unless_connected`, `accept_plaintext_only_connected` | kroopt core | — | met (v0.3) |
| No unauthenticated plaintext | PROVEN (+ AEAD ASSUMED) | `aead_open_failure_no_plaintext`, `buffered_plaintext_authenticated`, `buffered_plaintext_provenance` | kroopt core | rests on AEAD correctness (ASSUMED) | met |
| Per-epoch nonce uniqueness | PROVEN | `nonce_unique_within_epoch` | kroopt core | — | met |
| Sequence monotonic; overflow fatal | PROVEN | `successful_open_increments_read_seq`, `successful_registered_seal_increments_write_seq`, `no_crypto_on_write_seq_overflow`, `budget_failed_seal_does_not_advance_write_seq` | kroopt core | — | met |
| Transcript binding to exact wire bytes | PROVEN (hash ASSUMED/KAT) | `connected_requires_finished_verified` + transcript commit theorems | kroopt core | hash-provider correctness is ASSUMED | met |
| Parser bounds safety | PROVEN (+ fuzz TESTED) | `parser_bounds_safe`, `reader_in_bounds`; `kroopt-parse-fuzz` | kroopt core | — | met |
| Operation-id correlation (no stale crypto) | PROVEN | `stale_crypto_result_rejected`, `stale_crypto_result_no_plaintext` | kroopt core | — | met |
| Pending-op boundedness / cleanup | PROVEN + TESTED | outstanding-only `PendingCryptoOps`, cleared on terminal | kroopt core | full async stale-result matrix for an IO interpreter (RFC 040) | v1 |
| Terminal-after-close discipline | PROVEN | `no_plaintext_after_terminal`, `terminal_absorbing`, `terminal_no_error` | kroopt core | — | met |

## Negotiation and configuration — PROVEN / TESTED

| Claim | Status | Evidence | Owner | Remaining gap | Release gate |
|---|---|---|---|---|---|
| Config capability validation total/deterministic | PROVEN (total fn) + TESTED | `validateServerConfigCapabilities`; `kroopt-capabilities-test`, `kroopt-config-test` | kroopt | — | met |
| Named-group authorization (x25519-first, allow-list) | TESTED (+ structural) | `kroopt-handshake-test`; live P-256 + rejection interop | kroopt | — | met |
| `supported_groups`/`key_share` consistency (incl. strict absent-SG reject) | TESTED | parse-time consistency check (RFC 8446 §4.2.8); `noSgCH` replay + EndToEnd consistency fixtures | kroopt | — | met (HIGH-3) |
| ALPN offered-and-allowed | TESTED | `kroopt-handshake-test`; live interop | kroopt | — | met |
| Certificate/key config-lint | TESTED | leaf-key compatibility lint; `kroopt-provision-test` | kroopt | broader operational lint (chain order, SAN/expiry) | v0.4 (MEDIUM-3) |
| Alert/close terminal discipline | PROVEN | terminal theorems above; `kroopt-close-test` | kroopt core | — | met |

## Secrets and observability

| Claim | Status | Evidence | Owner | Remaining gap | Release gate |
|---|---|---|---|---|---|
| Trace is secret-free | TESTED (by construction) | no `ByteArray`/secret handle in `TraceEvent`; `kroopt-trace-test` | kroopt | — | met |
| Server private-key zeroization | TESTED (C-owned) | native secret arena; `kroopt-nativesecret-test`, ASan | kroopt + native arena | — | met |
| Connection traffic-secret zeroization | **BEST-EFFORT** | logical invalidation only; secrets in Lean-GC `ByteArray`s | kroopt | native traffic-secret arena + IO interpreter + pure↔IO correspondence | **v1 gate** (RFC 040) |

## Borrowed cryptography — ASSUMED (HACL\*/EverCrypt) + KAT/interop TESTED

> **⚠ Byte-level provenance anchoring is PENDING (known gap).** Every row below inherits the upstream
> Project Everest verification claim — but that inheritance holds *only if* the vendored bytes under
> `Kroopt/Native/hacl/` provably **are** the named upstream verified artifact. That anchor does **not yet
> exist**: there is no recorded upstream commit/release, no per-file provenance manifest, and no gate
> verifying the tree against upstream. The KAT/interop evidence below proves the primitives *behave*
> correctly; it does **not** establish byte identity to upstream — a functionally-correct reimplementation
> would pass the same vectors. Until strict anchoring lands (dedicated HACL\*/EverCrypt vendoring &
> provenance RFC), these are ASSUMED dependencies **with a known provenance gap**, not fully anchored
> inherited-verified claims.

| Claim | Status | Evidence (KAT vector / suite) | Owner | Remaining gap | Release gate |
|---|---|---|---|---|---|
| **Vendored byte identity = named upstream verified artifact** | **ASSUMED — provenance anchor PENDING** | none yet — KAT/interop prove behavior, not identity | kroopt (vendoring discipline) | strict byte-level anchor: pinned upstream commit + per-file manifest + offline provenance gate | blocks real release sidecar (RFC 030 Stage B) |
| AEAD correctness (AES-128/256-GCM, ChaCha20-Poly1305) | ASSUMED + KAT TESTED | NIST GCM TC4; RFC 8439; `kroopt-hacl-test` | HACL\*/Project Everest | AES-GCM on the wire (interop) | v0.4 |
| HKDF / HMAC correctness | ASSUMED + KAT TESTED | RFC 5869 §A.1; RFC 4231 §4.2; `kroopt-hacl-test` | HACL\* | — | met |
| ECDHE correctness (X25519, P-256) | ASSUMED + KAT/interop TESTED | RFC 7748 §6.1; NIST CAVP KAS; `kroopt-hacl-test` + interop | HACL\* | — | met |
| Signature correctness (Ed25519) | ASSUMED + KAT/interop TESTED | RFC 8032 vectors; `kroopt-hacl-test` + cert interop | HACL\* | ECDSA-P256 / RSA-PSS bound but **not advertised** | v0.4+ |
| CSPRNG quality | ASSUMED | OS `getrandom`, fail-closed (RFC 034) | OS | — | met |
| Constant-time / side-channel resistance | ASSUMED | property of HACL\*/Vale | HACL\*/Vale | never proved here | n/a (OUTSCOPE) |

## Boundary, integration, and interop

| Claim | Status | Evidence | Owner | Remaining gap | Release gate |
|---|---|---|---|---|---|
| FFI memory safety | TESTED (ASan/UBSan), not PROVEN | `scripts/sanitizer-check.sh` (system gcc) | kroopt shim | not a proof target | met (pre-stable) |
| Interpreter faithfulness | TESTED, not PROVEN | `kroopt-correspondence-test`; fake interpreter | kroopt | pure↔IO correspondence for a production IO interpreter | v1 |
| Live constrained interop | TESTED | `scripts/tls-interop.sh` — openssl/python/curl, blocking + reactor | kroopt | AES-GCM on the wire | v0.4 |
| Browser-grade interop | NOT CLAIMED | — | kroopt | full browser matrix | post-v0.4 |
| Global / listener-level DoS | per-connection bounds PROVEN/TESTED; **listener-wide DELEGATED** | resource-budget bounds + handshake/idle timeouts (kroopt); admission/rate-limit/global budgets (iotakt + jemmet) | kroopt (per-connection) · iotakt + jemmet (global) | explicit threat-model declaration | v0.3 doc (threat-model increment) |

## What this matrix deliberately does **not** claim

Cryptographic secrecy / IND-CCA, peer certificate path validation, TLS 1.2 / DTLS / QUIC, 0-RTT,
tickets, HRR, KeyUpdate, mTLS, and the client role are all OUTSCOPE for the constrained server profile —
see [deferred scope](deferred-scope.md). The honest one-line summary kroopt always states: **it proves
the protocol holds together; it trusts HACL\*/EverCrypt that the cryptography is sound; it does not
prove the cryptography — and the byte-level provenance anchor binding the vendored tree to that upstream
verified artifact is currently pending (see the provenance-anchor row above).**
