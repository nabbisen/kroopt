# Proof gates, CI, and Lean hygiene

A verification-first project is only as trustworthy as the gates that keep the
proofs honest (RFC 022). kroopt enforces three, in CI and locally:

1. **Hygiene** (`scripts/check-hygiene.sh`) — no `sorry`, `axiom`, `unsafe`,
   `native_decide`, or `admit` in the strict zones (`Kroopt/Core`, `Kroopt/Parse`,
   `Kroopt/Proofs`, `Kroopt/Error.lean`). A syntactic scan.
2. **Dependency** (`scripts/check-deps.sh`) — the pure zones never import the
   runtime, native, or transport layers (`Kroopt.Conn`, `Kroopt.Crypto`,
   `Kroopt.Native`, `Iotakt`, `Henret`). This is what keeps the verified core
   pure and the proof/runtime boundary intact.
3. **Axiom** (`scripts/check-axioms.sh`) — the semantic complement: it
   `#print axioms` for every public theorem and asserts none depends on `sorryAx`
   (a `sorry` leaking in through a dependency) and that the axiom set stays within
   `{propext, Quot.sound, Classical.choice}`. A `sorry` that the syntactic scan
   misses still surfaces here.

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs the full build, all
test suites, the parser fuzzer, and all three gates on every push and pull
request. The build itself is a gate too: Lean rejects an incomplete proof, so a
green `lake build` already means every theorem is fully checked.
