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

/-!
The handshake/ClientHello byte budgets above are the budget primitives that run on the inbound path
(`chargeHandshakeBytes`, `chargeClientHelloBytes`), charged against the connection's validated
`ResourceLimits` (RFC 042 B1). The other resource bounds are enforced by their own running mechanisms,
not by a budget charge, so they are proved/tested where that mechanism lives rather than here (RFC 042 C2):

* **inbound record size** — the parser rejects an over-length record (`Parse.Reader.lengthExceedsMax →
  .oversizedRecord`), surfaced on the record path as `recordFailAlert (alertForParseError .oversizedRecord)`;
* **progress-loop steps** — bounded structurally by `driveEvents` fuel recursion (`progressBudget`, now the
  connection's `maxProgressStepsPerCall`); the recursion terminates in at most `fuel` steps by construction;
* **extension count** — bounded transitively by `maxClientHelloBytes` (extensions live inside the
  byte-bounded ClientHello) and the proven parser bounds-safety;
* **outbound ciphertext** — bounded by the interpreter egress backstop (`TlsConn.send`, RFC 042 A1), tested
  against `maxPendingCiphertextBytes`; it is interpreter buffer management, not a core-proven property.
-/

end Kroopt.Core.Proofs
