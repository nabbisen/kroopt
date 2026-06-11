# Introduction

kroopt is a Lean 4 TLS 1.3 secure-channel library. It sits between
[iotakt](https://github.com/) (non-blocking byte transport) and a higher-level
HTTP layer such as jemmet. Its design goal is a **pure verified protocol core**:
the TLS state machine is a total Lean function, `Kroopt.Core.step`, that emits
[output actions](boundary.md); a thin interpreter executes those actions over
real crypto and real sockets and never makes protocol decisions of its own.

This separation is what lets kroopt carry machine-checked safety guarantees —
for example, that application plaintext is never emitted before the handshake is
complete — into the code that actually runs.

## Status

This documentation tracks the implementation milestones defined in the
[ROADMAP](../../ROADMAP.md) and the [RFC set](../../rfcs/README.md).

**M0 (verified-core skeleton) is implemented:** the state/event/action model,
the `step` transition function, and the first five structural proofs build with
no `sorry`/`axiom`/`unsafe` and pass the proof-hygiene and module-dependency
gates. See the [theorem inventory](theorem-inventory.md).

No real cryptography and no sockets exist yet; those arrive at M2–M7 per the
roadmap.
