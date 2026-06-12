import Kroopt.Core.KeyScheduleDriver

/-!
# Kroopt.Proofs.KeyScheduleDriver

Discipline and progress proofs for the pure key-schedule orchestrator
(`Kroopt.Core.KeyScheduleDriver`). These are the properties the eventual `step`
integration relies on:

* `advance_emits_schedule_ops` — the driver only ever emits ECDHE/HKDF/install
  ops, never AEAD, signatures, or anything else. When wired into the handshake
  this is what keeps "no plaintext / no AEAD-open during key derivation" intact.
* `advance_progress` — every accepted result advances the phase by exactly one
  rank, so the schedule is finite (it reaches `complete` after a fixed number of
  results) and cannot loop.
* `advance_complete_terminal` — once `complete`, further results emit nothing.
* `start_emits_schedule_op` — the opening ECDHE op is a schedule op too.
-/

namespace Kroopt.Core.Proofs

open Kroopt.Core.KeyScheduleDriver

/-- The driver emits only key-schedule operations (never AEAD, signature, or
randomness ops). -/
theorem advance_emits_schedule_ops
    (s s' : State) (r : Kroopt.Core.CryptoResult) (ops : List Kroopt.Core.CryptoOp)
    (hok : advance s r = .ok (s', ops)) :
    ops.all isScheduleOp = true := by
  unfold advance at hok
  split at hok <;>
    first
      | (obtain ⟨_, rfl⟩ := hok; simp [isScheduleOp, expand])
      | simp_all

/-- Each accepted result advances the phase by exactly one rank — the schedule is
finite and strictly progressing. -/
theorem advance_progress
    (s s' : State) (r : Kroopt.Core.CryptoResult) (ops : List Kroopt.Core.CryptoOp)
    (hne : s.phase ≠ .complete)
    (hok : advance s r = .ok (s', ops)) :
    s'.phase.rank = s.phase.rank + 1 := by
  unfold advance at hok
  split at hok <;>
    first
      | (obtain ⟨rfl, _⟩ := hok; simp_all [Phase.rank])
      | simp_all [Phase.rank]

/-- `complete` is absorbing: any further result emits no operations and leaves the
state unchanged. -/
theorem advance_complete_terminal
    (s : State) (r : Kroopt.Core.CryptoResult) (h : s.phase = .complete) :
    advance s r = .ok (s, []) := by
  unfold advance
  split <;> simp_all

/-- The opening operation of the schedule is itself a schedule op. -/
theorem start_emits_schedule_op
    (suite : Kroopt.Core.CipherSuite) (peer eh hs ap : ByteArray) :
    isScheduleOp (start suite peer eh hs ap).2 = true := by
  simp [start, isScheduleOp]

end Kroopt.Core.Proofs
