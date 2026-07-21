# kroopt

[![License](https://img.shields.io/github/license/nabbisen/kroopt)](LICENSE)
[![Lean 4](https://img.shields.io/badge/Lean-4-blueviolet.svg)](lean-toolchain)
[![CI](https://github.com/nabbisen/kroopt/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

**A verification-first TLS 1.3 secure-channel library for Lean 4 — a pure, proven protocol core driven by a thin interpreter.**

> **Pre-production status.** Independent architecture review of `0.124.1` found eight open remediation
> blockers. kroopt is suitable for development and evaluation, but production/stable adoption is **NO-GO**
> until AR0–AR3 complete; stable/v1 additionally requires AR4. See the
> [current security state](docs/src/verification/current-security-state.md) and
> [remediation roadmap](ROADMAP.md#0-architecture-review-remediation-program-2026-07-13).

## Overview

kroopt turns a non-blocking byte transport into an encrypted, authenticated TLS 1.3
channel and presents a uniform plaintext connection upward. The protocol is a total
Lean function, `Kroopt.Core.step`, that makes every TLS decision and emits explicit
output actions; a thin interpreter executes those actions over real cryptography and
sockets and makes no protocol decisions of its own. That split is what carries
machine-checked safety properties — above all *no application plaintext before
`connected`* and *none from an unauthenticated record* — into the running code.

kroopt borrows its cryptographic primitives from the formally verified
[HACL\*/EverCrypt](https://github.com/hacl-star/hacl-star) (Project Everest) and
proves the *protocol structure* around them; it never hand-rolls a cipher.

## Why and when

A verified edge server (such as the [jemmet](https://github.com/nabbisen) HTTP
server it was built for) loses its value if it must sit behind an unverified TLS
terminator — the attack surface just moves to the proxy. kroopt exists so a Lean
server can terminate HTTPS itself with a small, auditable, verification-first
channel. Reach for it when you want TLS termination whose protocol-structural safety
is machine-checked rather than assumed, and you can accept a deliberately narrow
scope (see *Design notes*). Until the remediation gates close, use it for development
and evaluation rather than production traffic.

## Quick start

Requires the Lean toolchain pinned in [`lean-toolchain`](lean-toolchain), managed by
[elan](https://github.com/leanprover/elan). The pure core, parser, and proofs build
with no C toolchain; only the HACL\* FFI library and its KAT executables need a C
compiler. The canonical release profile additionally requires the declared
[gate environment](docs/src/operations/release-gate-environment.md) and
[`requirements-gate.txt`](requirements-gate.txt).

```sh
lake build                          # core + parser + proofs + test executables
lake exe kroopt-correspondence-test # production interpreter + real provider to `connected`
lake exe kroopt-hacl-test           # HACL* primitive KATs through the Lean FFI
lake exe kroopt-parse-fuzz 40000    # parser / ClientHello fuzz harness

./scripts/check-hygiene.sh          # gate: no sorry/axiom/unsafe in strict zones
./scripts/check-deps.sh             # gate: pure-zone module isolation
./scripts/check-axioms.sh           # gate: no sorryAx; axioms within the whitelist
```

`lake build` produces all test executables (`kroopt-*-test`); the suite and the
three proof gates run in CI on every change.

## Design notes

- **Borrow crypto, prove protocol.** Cipher math is delegated to verified HACL\*;
  kroopt proves the TLS state machine, record layer, transcript binding, and action
  discipline. The trust boundary is explicit: protocol structure is *proven*, the
  primitives are *assumed* (inherited-verified), wire interop is *tested*.
- **Pure core, thin interpreter.** The architecture requires protocol decisions to live in
  `Kroopt.Core.step`, with the interpreter executing its actions. Correspondence is tested, not proved for
  the IO boundary, and RFC 048 tracks the open protected-epoch fallback/construction violation.
- **No early or unauthenticated plaintext.** Both are proof targets, not conventions.
- **Deliberately narrow.** Server role, TLS 1.3 only, no HelloRetryRequest, no 0-RTT /
  tickets / KeyUpdate / mTLS. The real provider advertises AES-128-GCM, AES-256-GCM,
  ChaCha20-Poly1305, X25519, P-256, and Ed25519; all three suites and both groups have constrained live
  interop evidence. Provider/certificate capability mismatches fail validation, but endpoint cipher
  allow-list authorization remains open B1 and must not be inferred from provider validation.
- **Secret residency is staged.** The server private key is held behind an opaque native handle and has
  tested C-owned zeroization. Connection traffic secrets currently pass through Lean-GC-managed
  `ByteArray`s and receive best-effort logical invalidation only; native traffic-secret residency remains
  the stable/v1 gate in RFC 040.

## Status

kroopt is a proof-backed **pre-production** constrained TLS 1.3 server implementation. The core, parser,
record layer, key schedule, HACL\* provider, typed server flight, production interpreter, real socket path,
and constrained OpenSSL/Python/curl interop exist. Those capabilities do not close the architecture-review
findings: endpoint cipher policy, strict ClientHello framing, live deadline enforcement, unforgeable
validated construction, total record-phase rejection, certificate-chain representation, and traffic-secret
residency remain scheduled work. Canonical-gate portability was closed by RFC 051, but every candidate still
requires its own exact-revision ledger.

For current capability, evidence classification, blockers, and the next milestone, use the
[current security state](docs/src/verification/current-security-state.md). The [CHANGELOG](CHANGELOG.md)
is release history; the [ROADMAP](ROADMAP.md) is sequencing, not evidence that a milestone has passed.

## Documentation

Full documentation lives in [`docs/src`](docs/src) (an [mdBook](https://rust-lang.github.io/mdBook/)):

- [Introduction](docs/src/introduction.md)
- **Architecture** — the boundary and the pipeline from parser to handshake to
  `TlsConn`: start at [Boundary and non-goals](docs/src/architecture/boundary.md).
- **Cryptography and the trust boundary** — the FFI contract, key schedule, and
  provenance: [Crypto provider and FFI contract](docs/src/crypto/crypto-ffi-contract.md),
  [Vendored crypto: provenance and licensing](docs/src/crypto/third-party.md).
- **Verification** — [Theorem inventory](docs/src/verification/theorem-inventory.md)
  and the [Proof assumptions register](docs/src/verification/proof-assumptions.md). Begin with the
  [current security state](docs/src/verification/current-security-state.md) for the version-current posture.

The development plan is the [RFC set](rfcs/README.md), managed under the
[RFC lifecycle policy](rfcs/done/000-rfc-lifecycle-policy.md), and the
[ROADMAP](ROADMAP.md).

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

kroopt vendors a portable-C subset of HACL\*/EverCrypt (with the KaRaMeL/kremlin
runtime) under [`Kroopt/Native/hacl/`](Kroopt/Native/hacl), redistributed verbatim
with its upstream licenses intact (the C is marked `linguist-vendored`, so GitHub
classifies the repository by its Lean 4 sources). See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and the
[provenance docs](docs/src/crypto/third-party.md).
