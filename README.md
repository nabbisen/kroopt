# kroopt

A Lean 4 TLS 1.3 secure-channel library with a **pure verified protocol core**.

kroopt sits between [iotakt](https://github.com/nabbisen/iotakt) (non-blocking
byte transport) and a higher-level HTTP layer such as jemmet. The TLS state
machine is a total Lean function, `Kroopt.Core.step`, that emits explicit output
actions; a thin interpreter executes those actions over real crypto and sockets
and never makes protocol decisions of its own. That separation carries
machine-checked safety properties into the running code.

## Status: M0 + M1 + M2 + M3 + M4 + M5 + M6 + M7 (verified core → live handshake → TlsConn runtime)

This tree implements milestones **M0**–**M5** from the [ROADMAP](ROADMAP.md). M0
fixes the pure-core/interpreter architecture; M1 adds the bounds-safe parsing
foundation; M2 adds the TLS 1.3 record model with the *no unauthenticated
plaintext* proof; M3 proves the record layer's cryptographic discipline (sequence
monotonicity, no nonce wrap, nonce uniqueness, key separation); M4 adds the
server handshake state machine (no HelloRetryRequest) and the exact-wire-byte
transcript; M5 wires the handshake into the live `step` dispatcher and drives the
**full synthetic handshake end-to-end through `step`** against a fake transport
and fake crypto provider — closing the v0.1 synthetic-core line. M6 adds the crypto
provider trusted boundary with the **operation-id correlation guard** proved over
the live handshake; the native HACL\*/EverCrypt shim is contracted with its build
deferred until HACL\* is vendored, so the deterministic fake provider still stands
in and there are no sockets yet. M7 adds the runtime layer — the `TlsConn` API
and the thin interpreter, which executes the core's actions over a (fake)
transport and provider and carries no protocol logic; the real iotakt binding is
a thin deferred adapter. These layers are built and proven first so the
protocol model and the running code cannot drift apart later (RFC 001–010, 014,
022, 024).

The headline M5 result: every M2/M3 safety theorem — above all *no early
plaintext* — **still holds over the live handshake**, which is the
proof/runtime correspondence contract.

What builds and is checked today:

- the pure core — `Kroopt.Core` (`Id`, `Common`, `CipherSuite`, `Record` with the
  TLS 1.3 record types and `SeqNo`, `Crypto`, `Nonce`, `Transcript` with the
  exact-byte binding, `State`, `Event`, `Action`, `RecordPath` with the live
  handshake dispatch, `Handshake` with the five transition functions, `Step`);
- the bounds-safe parser foundation — `Kroopt.Parse` (`Reader`, fixed-width and
  length-prefixed reads, the budgeted vector framer, the record framer
  `tryTakeRecord`, the `Handshake` ClientHello parser, inner-plaintext parsing,
  CCS classification);
- ~38 machine-checked theorems in `Kroopt.Proofs`, including *no early plaintext*
  and *no unauthenticated plaintext* **preserved over the live handshake**, *no
  silent sequence wrap*, nonce uniqueness, key separation, *legal handshake
  transitions*, *client-Finished-before-connected*, *exact transcript byte
  binding*, *stale-crypto-result rejection* (operation-id correlation), and parser
  bounds-safety — all with **no `sorry`/`axiom`/`unsafe`**,
  depending only on `propext` (some also `Quot.sound`, several on no axioms);
- deterministic tests — model (9), parser (18), record (19), nonce/seq (12),
  handshake/transcript (10), end-to-end through `step` (12), crypto provider +
  correlation (11), TlsConn + interpreter (13), all green, plus a parser/ClientHello
  fuzz harness;
- two CI gates that run from M0: proof hygiene and module-dependency isolation.

See the [theorem inventory](docs/src/theorem-inventory.md) and
[proof-assumptions register](docs/src/proof-assumptions.md).

## Build and test

Requires the Lean toolchain pinned in [`lean-toolchain`](lean-toolchain)
(`leanprover/lean4:v4.15.0`), managed by [elan](https://github.com/leanprover/elan).
No mathlib, no C toolchain, no network reactor are needed for M0.

```sh
lake build                    # build the core + parser + proofs + test exes
lake exe kroopt-model-test    # M0 model test (drives `step`)
lake exe kroopt-parse-test    # M1 parser unit + negative tests
lake exe kroopt-record-test   # M2 record-model unit + negative tests
lake exe kroopt-nonce-test    # M3 sequence/nonce/key-separation tests
lake exe kroopt-handshake-test # M4 synthetic handshake + transcript tests
lake exe kroopt-e2e-test      # M5 full handshake end-to-end through `step`
lake exe kroopt-crypto-test   # M6 crypto provider + operation-id correlation tests
lake exe kroopt-conn-test     # M7 TlsConn API + non-blocking interpreter tests
lake exe kroopt-parse-fuzz    # parser + ClientHello smoke fuzzer (optional arg: iterations)
./scripts/check-hygiene.sh    # RFC 022 proof-hygiene gate
./scripts/check-deps.sh       # RFC 022 module-dependency gate
```

## Layout

```text
Kroopt.lean            root module (re-exports the M0 core)
Kroopt/
  Error.lean           typed, redaction-safe error/alert taxonomy
  Core/                pure verified core: types, records, nonce, transcript, handshake, step
  Parse/               pure bounds-safe parser/framer foundation (Reader, …)
  Crypto/              trusted boundary: provider capability model + fake provider
  Native/              C shim contract (kroopt.h) — HACL* build deferred
  Conn/                runtime layer: TlsConn API + thin interpreter + transport
  Proofs/              structural proofs over `step` and the parser
Tests/
  Model.lean           deterministic model test (drives `step`)
  Parse.lean           parser unit + negative tests
  Record.lean          record-model unit + negative tests
  Nonce.lean           sequence/nonce/key-separation tests
  Handshake.lean       synthetic handshake + transcript tests
  EndToEnd.lean        full handshake end-to-end through `step` (fake crypto/transport)
  Crypto.lean          provider capability + operation-id correlation tests
  Conn.lean            TlsConn + interpreter faithfulness tests
  Fuzz.lean            parser + ClientHello smoke fuzzer
scripts/               CI gates (hygiene, module dependencies)
docs/src/              mdbook documentation (incl. theorem inventory)
rfcs/                  RFC set, managed per rfcs/done/000 lifecycle policy
ROADMAP.md             milestones, dependency map, release staging
```

The development plan lives in the [RFC set](rfcs/README.md) and the
[ROADMAP](ROADMAP.md). RFCs are managed under the
[RFC lifecycle policy](rfcs/done/000-rfc-lifecycle-policy.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
