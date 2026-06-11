# kroopt

A Lean 4 TLS 1.3 secure-channel library with a **pure verified protocol core**.

kroopt sits between [iotakt](https://github.com/nabbisen/iotakt) (non-blocking
byte transport) and a higher-level HTTP layer such as jemmet. The TLS state
machine is a total Lean function, `Kroopt.Core.step`, that emits explicit output
actions; a thin interpreter executes those actions over real crypto and sockets
and never makes protocol decisions of its own. That separation carries
machine-checked safety properties into the running code.

## Status: M0 + M1 + M2 (verified core + parser + record model)

This tree implements milestones **M0**, **M1**, and **M2** from the
[ROADMAP](ROADMAP.md). M0 fixes the pure-core/interpreter architecture; M1 adds
the bounds-safe parsing foundation; M2 adds the TLS 1.3 record model with the
*no unauthenticated plaintext* proof. There is still no real cryptography and no
sockets — that is deliberate. These layers are built and proven first so the
protocol model and the running code cannot drift apart later (RFC 001–004, 022,
024).

What builds and is checked today:

- the pure core — `Kroopt.Core` (`Id`, `Common`, `CipherSuite`, `Record` with
  the TLS 1.3 record types, `Crypto`, `Transcript`, `State`, `Event`, `Action`,
  `RecordPath`, `Step`);
- the bounds-safe parser foundation — `Kroopt.Parse` (`Reader`, fixed-width and
  length-prefixed reads, the budgeted vector framer, the record framer
  `tryTakeRecord`, inner-plaintext parsing, CCS classification);
- nineteen machine-checked theorems in `Kroopt.Proofs`, including *no early
  plaintext* (`no_plaintext_emit_unless_connected`), *no unauthenticated
  plaintext* (`buffered_plaintext_authenticated`), AEAD-open-failure safety,
  terminal-state absorption, and parser bounds-safety — all with **no
  `sorry`/`axiom`/`unsafe`**, depending only on `propext` (some also
  `Quot.sound`);
- deterministic tests — an M0 model test (9 checks), an M1 parser test (18), an
  M2 record test (19), all green, plus a parser fuzz harness;
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
lake exe kroopt-parse-fuzz    # M1 parser smoke fuzzer (optional arg: iterations)
./scripts/check-hygiene.sh    # RFC 022 proof-hygiene gate
./scripts/check-deps.sh       # RFC 022 module-dependency gate
```

## Layout

```text
Kroopt.lean            root module (re-exports the M0 core)
Kroopt/
  Error.lean           typed, redaction-safe error/alert taxonomy
  Core/                pure verified core: types, State, Event, Action, step
  Parse/               pure bounds-safe parser/framer foundation (Reader, …)
  Proofs/              structural proofs over `step` and the parser
Tests/
  Model.lean           deterministic model test (drives `step`)
  Parse.lean           parser unit + negative tests
  Record.lean          record-model unit + negative tests
  Fuzz.lean            parser smoke fuzzer
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
