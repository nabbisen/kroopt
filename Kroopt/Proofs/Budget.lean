import Kroopt.Core.Budget

/-!
# Kroopt.Proofs.Budget

DoS-bound proofs over the resource-budget primitives (RFC 019). The essential
property: an *accepted* charge never leaves a counter above its configured
ceiling, and an over-limit charge is rejected deterministically. Together these
mean an attacker cannot drive a kroopt-owned counter past its bound — the budget
is a hard limit, not advisory.
-/

namespace Kroopt.Core.Proofs

open Kroopt Kroopt.Core

/-- An accepted handshake-byte charge leaves the counter within the ceiling
(the DoS bound). -/
theorem chargeHandshakeBytes_bounded
    (lim : ResourceLimits) (b b' : BudgetState) (n : Nat)
    (h : chargeHandshakeBytes lim b n = .ok b') :
    b'.handshakeBytesSeen ≤ lim.maxHandshakeBytes := by
  unfold chargeHandshakeBytes at h
  simp only [] at h
  split at h
  · exact absurd h (by simp)
  · rename_i hle
    simp only [Except.ok.injEq] at h
    subst h
    exact Nat.not_lt.mp hle

/-- An over-limit handshake-byte charge is rejected. -/
theorem chargeHandshakeBytes_rejects_over
    (lim : ResourceLimits) (b : BudgetState) (n : Nat)
    (h : b.handshakeBytesSeen + n > lim.maxHandshakeBytes) :
    chargeHandshakeBytes lim b n = .error .handshakeBytes := by
  unfold chargeHandshakeBytes
  simp only []
  rw [if_pos h]

/-- An accepted charge accounts for exactly the bytes charged. -/
theorem chargeHandshakeBytes_accounts
    (lim : ResourceLimits) (b b' : BudgetState) (n : Nat)
    (h : chargeHandshakeBytes lim b n = .ok b') :
    b'.handshakeBytesSeen = b.handshakeBytesSeen + n := by
  unfold chargeHandshakeBytes at h
  simp only [] at h
  split at h
  · exact absurd h (by simp)
  · simp only [Except.ok.injEq] at h; rw [← h]

/-- An accepted extension charge stays within the count ceiling. -/
theorem chargeExtensions_bounded
    (lim : ResourceLimits) (b b' : BudgetState) (k : Nat)
    (h : chargeExtensions lim b k = .ok b') :
    b'.extensionsSeen ≤ lim.maxExtensions := by
  unfold chargeExtensions at h
  simp only [] at h
  split at h
  · exact absurd h (by simp)
  · rename_i hle
    simp only [Except.ok.injEq] at h
    subst h
    exact Nat.not_lt.mp hle

/-- An accepted progress-step charge stays within the per-call ceiling — the
event loop cannot exceed its step budget (RFC 010 §10). -/
theorem chargeProgressStep_bounded
    (lim : ResourceLimits) (b b' : BudgetState)
    (h : chargeProgressStep lim b = .ok b') :
    b'.progressStepsThisCall ≤ lim.maxProgressStepsPerCall := by
  unfold chargeProgressStep at h
  simp only [] at h
  split at h
  · exact absurd h (by simp)
  · rename_i hle
    simp only [Except.ok.injEq] at h
    subst h
    exact Nat.not_lt.mp hle

/-- An oversized record is rejected before allocation. -/
theorem checkRecordSize_rejects_over
    (lim : ResourceLimits) (n : Nat) (h : n > lim.maxRecordPlaintextBytes) :
    checkRecordSize lim n = .error .recordSize := by
  unfold checkRecordSize
  rw [if_pos h]

end Kroopt.Core.Proofs
