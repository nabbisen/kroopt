import Kroopt.Core.Step

/-!
# Kroopt.Proofs.Basic

Foundational structural theorems over `Kroopt.Core.step` (RFC 002 §7, RFC 022 §6).

These are the first proofs in the inventory. They are genuine (no `sorry`,
`axiom`, or `unsafe` — RFC 022 §4) and target the real `step`, not a separate
informal model (RFC 002 §10).
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- **Determinism.** `step` is a pure total function: a given state and event
have exactly one result (RFC 002 §7). -/
theorem step_deterministic (s : State) (ev : InputEvent) (r₁ r₂ : StepResult)
    (h₁ : step s ev = r₁) (h₂ : step s ev = r₂) : r₁ = r₂ := by
  rw [← h₁, ← h₂]

/-- **Terminal absorbing.** In a terminal phase (`closed` or `failed`), every
event leaves the state unchanged and emits no actions (RFC 013 §7). -/
theorem terminal_absorbing
    (s s' : State) (ev : InputEvent) (acts : List OutputAction)
    (ht : s.handshake.isTerminal = true)
    (h : step s ev = .ok (s', acts)) :
    s' = s ∧ acts = [] := by
  unfold step at h
  rw [ht] at h
  simp only [if_true, absorbTerminal, Except.ok.injEq, Prod.mk.injEq] at h
  exact ⟨h.1.symm, h.2.symm⟩

/-- A terminal step never errors (it always absorbs). -/
theorem terminal_no_error
    (s : State) (ev : InputEvent)
    (ht : s.handshake.isTerminal = true) :
    step s ev = .ok (s, []) := by
  unfold step
  rw [ht]
  simp [absorbTerminal]

end Proofs
end Kroopt.Core
