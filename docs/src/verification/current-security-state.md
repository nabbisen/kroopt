# Current security state

This page is the **single source of truth** for kroopt's *current* capability and security posture. Where
any other page disagrees, **this page wins** — older pages may describe earlier milestones and are being
brought into line or marked historical. If you are deciding what to trust about kroopt, start here.

Evidence baseline: released `0.124.1`, followed by the accepted AR0–AR4 planning package on `main`
(2026-07-13). No AR remediation implementation is claimed by this page until its RFC and candidate-specific
gate evidence land.

## Readiness disposition

| Decision | Current state |
|---|---|
| Development and evaluation | permitted on the pre-1.0 line |
| Production adoption | **NO-GO** until AR0–AR3 and their evidence gates complete |
| Stable/v1 | **NO-GO** until AR0–AR4, including RFC 040 native traffic-secret residency |
| Canonical gate | the reviewed `0.124.1` environment failed 35/37; RFC 051 owns the AR0 portability repair and a fresh clean candidate ledger |

## Open architecture-review blockers

| Finding | Current gap | Scheduled closure |
|---|---|---|
| B1 | endpoint cipher allow-list does not authorize the parser-selected suite | RFC 045 / AR1 |
| B2 | ClientHello parsing is bounded but does not enforce all exact nested framing | RFC 046 / AR1 |
| B3 | live drivers do not generate the modeled handshake/idle deadline events | RFC 047 / AR2 |
| B4 | validated config/provider construction is bypassable and protected flight can fall back to plaintext | RFC 048 / AR1 |
| B5 | invalid record phase/content combinations can be silently ignored | RFC 049 / AR1 |
| B6 | connection traffic secrets remain in Lean `ByteArray` storage | truthful wording in RFC 053 / AR0; native residency in RFC 040 / AR4 |
| B7 | the canonical full-release gate was not portable in the reviewed environment | RFC 051 / AR0 |
| B8 | a configured certificate chain is represented as one TLS `CertificateEntry` | RFC 050 / AR2 |

**Next milestone:** AR0 — finish RFC 053 claim reconciliation and RFC 051 gate portability/registry work,
then retain a clean candidate-specific full-release ledger. None of B1–B8 is closed merely by scheduling it.

## Profile in one line

A **constrained TLS 1.3 server profile** — *not* full browser-grade TLS 1.3:

```text
no HelloRetryRequest · server role only · separate TLS/plaintext listeners ·
configured certificate presentation (no peer-chain validation) ·
constrained live interop · proof-backed core safety properties ·
tested native crypto boundary · best-effort traffic-secret zeroization.
```

## Cryptographic capability the provider implements today

This is the capability the **real provider advertises** — i.e. what an endpoint config may select and
serve end-to-end (capability validation rejects anything outside it):

| Family | Advertised / servable now | KAT (NIST/RFC vectors) | Live wire interop |
|---|---|---|---|
| `TLS_AES_128_GCM_SHA256` | yes | yes (NIST GCM TC4) | yes |
| `TLS_AES_256_GCM_SHA384` | yes | yes (NIST GCM TC4) | yes |
| `TLS_CHACHA20_POLY1305_SHA256` | yes | yes | yes |
| x25519 | yes | yes (RFC 7748) | yes |
| secp256r1 (P-256) | yes | yes (NIST CAVP) | yes |
| SHA-256 / SHA-384 | yes | yes (FIPS 180-4) | via handshake / AES-256 path |
| HKDF-SHA-256 | yes | yes (RFC 5869) | via handshake |
| **Ed25519** signatures | **yes (the only advertised scheme)** | self-consistency (RFC 8032 vectors) | yes (cert) |
| ECDSA-P256, RSA-PSS signatures | **no** — see below | no | no |

Three distinctions matter and are easy to misread elsewhere:

- **Signatures are Ed25519-only today.** The real provider's advertised `signatureSchemes` is `[ed25519]`.
  ECDSA-P256 and RSA-PSS have signing code and HACL\* bindings present, but they are **not advertised**,
  so a config requiring an ECDSA or RSA certificate is **rejected at validation** — they are not a
  current capability. (The *fake* provider used in model tests advertises all three by design; that is a
  test artifact, not the real surface.)
- **AES-GCM is KAT'd and wire-tested.** Both AES-GCM suites are advertised, pass NIST known-answer tests
  through the FFI, and complete live OpenSSL interop. This is crypto/wire evidence, not proof that endpoint
  cipher allow-lists authorize selection; B1 remains open until RFC 045.
- **"Provider advertises" ≠ "a given endpoint advertises."** Each validated endpoint config selects a
  subset of the advertised set. Implementations are **vendored HACL\*/EverCrypt** (provenance, version,
  and license in [third-party crypto](../crypto/third-party.md); the native shim is built and exercised
  under ASan/UBSan — **live**, not deferred).

## Live interop tested today

Three independent clients — **OpenSSL 3.x `s_client`, Python `ssl`, and curl 8.x** — over both the
blocking and the non-blocking reactor driver: handshakes with AES-128-GCM, AES-256-GCM, and
ChaCha20-Poly1305; x25519 and P-256 group coverage; an Ed25519 server certificate; application-data
round-trip; an explicitly observed graceful `close_notify`; and a rejection case (an x25519-only listener
refuses a P-256-only client — no HRR).
GREASE tolerance is tested only for a named-group and a cipher-suite GREASE value alongside valid offers
(RFC 8701); other GREASE positions are browser-grade follow-up.
**Browser-grade interop is not claimed** — see
[constrained vs browser-grade](../interop/constrained-vs-browser-grade.md).

## Security-state summary

| Area | Status |
|---|---|
| Core: no plaintext before `connected` | PROVEN |
| No unauthenticated plaintext | PROVEN (+ AEAD correctness ASSUMED) |
| Nonce / sequence discipline | PROVEN (+ concrete nonce KAT/interop TESTED) |
| Transcript binding | PROVEN over exact bytes (hash provider ASSUMED/TESTED) |
| Parser bounds | PROVEN (+ fuzz TESTED) |
| Crypto primitive correctness | ASSUMED from HACL\*/EverCrypt (KAT/interop TESTED) |
| FFI memory safety | TESTED (ASan/UBSan); not PROVEN |
| Server private key zeroization | TESTED, C-owned |
| Traffic-secret zeroization | **BEST-EFFORT only** — stable/v1 gate (see below) |
| Interpreter faithfulness | TESTED, not PROVEN |
| Operational counters | driven internally in the live driver (0.99.0-dev); **no export** (v0.4) |
| Live constrained interop | TESTED |
| Browser-grade interop | NOT CLAIMED |
| Global / listener-level DoS | per-connection bounds owned by kroopt; **listener-wide admission is an iotakt/jemmet responsibility** (see [threat model](threat-model.md)) |

The full claim-by-claim matrix (status · evidence · owner · remaining gap · release gate) is the
[trust matrix](trust-matrix.md).

## Traffic-secret zeroization — the standing stable/v1 gate

This separation is deliberate and must remain visible:

```text
Server private key:      TESTED C-owned zeroization.
Connection traffic secrets:  BEST-EFFORT logical invalidation, NOT production zeroization
  (they live in Lean-GC-managed ByteArrays). Stable/v1 gate: native traffic-secret arena +
  IO production interpreter + pure↔IO correspondence (RFC 040).
```

Best-effort invalidation does not defend against core dumps, swap, process-memory disclosure, crash
diagnostics, or copies made inside borrowed crypto — those are classified in the
[threat model](threat-model.md).

## Historical pages and conflict policy

Treat milestone-specific capability statements on these pages as **historical and superseded by this page**
where they conflict: `crypto/native-crypto.md`, `crypto/third-party.md`,
`architecture/record-protection.md`, `architecture/handshake.md`, `architecture/live-handshake.md`,
`architecture/cert-presentation.md`, `crypto/provisioning.md`, `verification/proof-assumptions.md`.
Phrases like "no AES-GCM", "ChaCha-only", "OpenSSL/curl pending", "native build deferred", or "metrics
planned/not emitted" are earlier-milestone text. Release-specific gate counts in CHANGELOG remain historical
claims about those revisions and are not evidence for the current working tree.
