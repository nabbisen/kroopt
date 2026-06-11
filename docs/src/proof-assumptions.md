# Proof assumptions register

This register lists every assumption the kroopt verified core's proofs depend on
beyond Lean's trusted kernel (RFC 022 §4). The goal is that the trusted base is
small, explicit, and auditable.

## Lean kernel and standard axioms

The M0 proofs depend only on Lean's standard, sound axioms:

* `propext` — propositional extensionality (used by `simp`/rewriting). Four of
  the five M0 theorems use it; `step_deterministic` uses no axioms at all.

No proof depends on `sorryAx`. This is enforced two ways:

1. `scripts/check-hygiene.sh` rejects any `sorry`/`axiom`/`unsafe`/`admit`/
   `native_decide` as code in the strict zones (`Kroopt/Core`, `Kroopt/Proofs`).
2. `#print axioms` on each theorem (see `theorem-inventory.md`) shows only
   `propext`.

## Project-local assumptions

**None at M0–M1.** The core and parser foundation are self-contained: no `axiom`
declarations, no appeals to unproven lemmas, no trusted external facts. Every
parser primitive that runs in a strict zone carries a bounds-safety proof (see
`theorem-inventory.md`).

### Tested-but-not-yet-proved helpers (explicit follow-up tasks)

RFC 003 §12 permits "tested trusted helpers with explicit follow-up proof
tasks." There is currently one:

* `Reader.takeCountedItems` (the fuel-bounded item combinator) is exercised by
  unit tests and the fuzz harness, and is structurally terminating (recursion on
  explicit fuel), but its bounds-safety *lemma* (`takeCountedItems_bounds`, under
  a bounds-safe-item hypothesis) is scheduled for M4 alongside the extension-list
  parser that first uses it. It is not yet relied upon by any verified theorem.

## Assumptions deferred to later milestones (not yet in the tree)

These will become explicit trust-boundary assumptions when their layer lands.
They are recorded now so the eventual trusted base is anticipated, not
discovered:

* **Crypto provider correctness (M6, RFC 008/009).** AEAD seal/open, HKDF, X25519,
  signatures, and SHA-2 are assumed correct as provided by HACL\*/EverCrypt.
  kroopt proves it *uses* them correctly (nonce discipline, key separation,
  transcript binding); it does not re-prove the primitives. This will be the
  single largest trusted component and will be justified by known-answer tests
  and sanitizer runs, not by Lean proof.
* **FFI boundary faithfulness (M6, RFC 009/024).** The C shim is assumed to honour
  the documented ownership and result-correlation contract. Justified by tests
  and sanitizers, not proof.
* **Interpreter faithfulness (M7, RFC 010).** The interpreter is assumed to
  execute each `OutputAction` exactly as specified and to feed back only
  correctly-correlated events. Justified by the deterministic harness comparing
  interpreter behaviour against the action stream (RFC 014).

Each deferred item will get its own dated entry here when the corresponding code
is introduced, including how the assumption is discharged or bounded.
