# kroopt

A Lean 4 TLS 1.3 secure-channel library with a **pure verified protocol core**.

kroopt sits between [iotakt](https://github.com/nabbisen/iotakt) (non-blocking
byte transport) and a higher-level HTTP layer such as jemmet. The TLS state
machine is a total Lean function, `Kroopt.Core.step`, that emits explicit output
actions; a thin interpreter executes those actions over real crypto and sockets
and never makes protocol decisions of its own. That separation carries
machine-checked safety properties into the running code.

## Status: M0 (verified-core skeleton)

This tree implements milestone **M0** from the [ROADMAP](ROADMAP.md): the
state/event/action model, the `step` transition function, and the first
structural proofs. There is no real cryptography and no sockets yet — that is
deliberate. M0 fixes the architecture so the protocol model and the runtime
cannot drift apart later (RFC 001, 002, 022, 024).

What builds and is checked today:

- the pure core — `Kroopt.Core` (`Id`, `Common`, `CipherSuite`, `Record`,
  `Crypto`, `Transcript`, `State`, `Event`, `Action`, `Step`);
- five machine-checked theorems in `Kroopt.Proofs`, including *no early
  plaintext* (`no_plaintext_emit_unless_connected`) and terminal-state
  absorption — all with **no `sorry`/`axiom`/`unsafe`**, depending only on
  `propext`;
- a deterministic model test that drives `step` directly (9 checks, all green);
- two CI gates that run from M0: proof hygiene and module-dependency isolation.

See the [theorem inventory](docs/src/theorem-inventory.md) and
[proof-assumptions register](docs/src/proof-assumptions.md).

## Build and test

Requires the Lean toolchain pinned in [`lean-toolchain`](lean-toolchain)
(`leanprover/lean4:v4.15.0`), managed by [elan](https://github.com/leanprover/elan).
No mathlib, no C toolchain, no network reactor are needed for M0.

```sh
lake build                    # build the core library + proofs + test exe
lake exe kroopt-model-test    # run the deterministic model test
./scripts/check-hygiene.sh    # RFC 022 proof-hygiene gate
./scripts/check-deps.sh       # RFC 022 module-dependency gate
```

## Layout

```text
Kroopt.lean            root module (re-exports the M0 core)
Kroopt/
  Error.lean           typed, redaction-safe error/alert taxonomy
  Core/                pure verified core: types, State, Event, Action, step
  Proofs/              structural proofs over `step`
Tests/Model.lean       deterministic model test (drives `step`)
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
