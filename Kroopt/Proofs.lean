import Kroopt.Proofs.Basic
import Kroopt.Proofs.ActionDiscipline

/-!
# Kroopt.Proofs

Structural proofs over the verified core's `step` function (RFC 002 §7,
RFC 015 §15.1, RFC 022). Pure, no `sorry`/`axiom`/`unsafe`.

* `Basic`           — determinism, terminal absorbing.
* `ActionDiscipline` — no early plaintext, no plaintext after terminal.

Later milestones add `Nonces`, `KeySeparation`, `StateMachine`, `Closure`,
`NoUnauthPlaintext`, and `ParserBounds` (requirements §6, RFC 005/006/007).
-/
