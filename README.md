# kroopt

[![License](https://img.shields.io/github/license/nabbisen/kroopt)](LICENSE)
[![Lean 4](https://img.shields.io/badge/Lean-4-blueviolet.svg)](lean-toolchain)
[![CI](https://github.com/nabbisen/kroopt/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

**A verification-first TLS 1.3 secure-channel library for Lean 4 — a pure, proven protocol core driven by a thin interpreter.**

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
scope (see *Design notes*).

## Quick start

Requires the Lean toolchain pinned in [`lean-toolchain`](lean-toolchain), managed by
[elan](https://github.com/leanprover/elan). The pure core, parser, and proofs build
with no C toolchain; only the HACL\* FFI library and its KAT executables need a C
compiler.

```sh
lake build                          # core + parser + proofs + test executables
lake exe kroopt-realhandshake-test  # live step-driven handshake to `connected`
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
- **Pure core, thin interpreter.** All protocol decisions live in `Kroopt.Core.step`;
  the interpreter only executes its actions. A proof/runtime-correspondence discipline
  keeps the two from drifting apart.
- **No early or unauthenticated plaintext.** Both are proof targets, not conventions.
- **Deliberately narrow.** Server role, TLS 1.3 only, no HelloRetryRequest, no 0-RTT /
  tickets / KeyUpdate / mTLS. The current crypto profile is a constrained, honest
  subset — `TLS_CHACHA20_POLY1305_SHA256`, X25519, Ed25519, SHA-256 — drawn from a
  fail-closed OS CSPRNG. Out-of-profile configurations are rejected at validation,
  never silently downgraded.
- **Secrets are handles.** Long-lived key material lives behind opaque, non-printable,
  non-serializable handles in zeroizable C-owned memory.

## Status

Under active development toward a real TLS 1.3 server interop milestone. The verified
core, parser, record layer, key schedule, real HACL\* provider, and a live
step-driven handshake to `connected` (with a real transcript, an in-core protected
client Finished, and handshake-message reassembly across records) are in place; the
production interpreter (now emitting the first typed handshake actions in place of
placeholder frames) and external-client interop are in progress. The ClientHello parser negotiates the signature scheme from the client's offer (selecting Ed25519 only when offered), which makes the constrained profile's interop limit explicit: a client that does not offer Ed25519 is rejected rather than served a certificate it cannot verify. Suite and group selection are bound the same way — kroopt negotiates ChaCha20-Poly1305 and X25519 from the client's offers and never a suite the provider cannot perform. The current milestone and
the running tally of machine-checked theorems are tracked in
[CHANGELOG.md](CHANGELOG.md) and the [ROADMAP](ROADMAP.md).

## Documentation

Full documentation lives in [`docs/src`](docs/src) (an [mdBook](https://rust-lang.github.io/mdBook/)):

- [Introduction](docs/src/introduction.md)
- **Architecture** — the boundary and the pipeline from parser to handshake to
  `TlsConn`: start at [Boundary and non-goals](docs/src/architecture/boundary.md).
- **Cryptography and the trust boundary** — the FFI contract, key schedule, and
  provenance: [Crypto provider and FFI contract](docs/src/crypto/crypto-ffi-contract.md),
  [Vendored crypto: provenance and licensing](docs/src/crypto/third-party.md).
- **Verification** — [Theorem inventory](docs/src/verification/theorem-inventory.md)
  and the [Proof assumptions register](docs/src/verification/proof-assumptions.md).

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
