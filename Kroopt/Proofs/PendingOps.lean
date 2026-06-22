import Kroopt.Core.Step

/-!
# Pending crypto-op accounting (RFC 037 §4.1)

The crypto-op budget is only a meaningful DoS / correlation-state control if
`PendingCryptoOps` measures **outstanding** operations — those registered and not yet
retired — rather than a cumulative history of every operation ever requested on the
connection.

Retirement is centralised: every correlated crypto result is consumed through
`handshakeOnGatingResult` (handshake-internal ops) or the record arms of
`handleCryptoResultCorrelated` (AEAD seal/open), and both retire the answered operation via
`State.clearOp` before doing anything else. These lemmas are the accounting backbone:
retiring an op removes exactly that op from the pending set, and never grows it. Combined
with the bounded-allocation guarantee (`allocOp` registers only below
`maxPendingCryptoOps`), the pending set stays a true outstanding-work count — the
end-to-end consequence (no handshake-internal op lingers once `connected`) is exercised by
`Tests.Handshake`.
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- **Retirement removes the op (RFC 037 §4.1).** Consuming a correlated crypto result
clears its operation id, and a cleared id is no longer outstanding. Every result-consumption
path (`handshakeOnGatingResult`, the AEAD arms of `handleCryptoResultCorrelated`) retires
through `State.clearOp`, so this is exactly "a consumed correlated result is removed from the
pending set". -/
theorem correlated_result_clears_op (s : State) (op : OperationId) :
    (s.clearOp op).pendingOps.contains op = false := by
  simp only [State.clearOp, PendingCryptoOps.contains, List.any_eq_false, List.mem_filter,
    and_imp]
  intro o _ hne
  simp only [bne, Bool.not_eq_true'] at hne
  simp only [Bool.not_eq_true]
  exact hne

/-- **Retirement never grows the pending set.** Clearing an op can only shrink (or keep)
the outstanding count, so retirement can never push the budget upward — only registration
can, and registration is gated by `allocOp` below `maxPendingCryptoOps`. -/
theorem clearOp_does_not_grow_pending (s : State) (op : OperationId) :
    (s.clearOp op).pendingOps.ops.length ≤ s.pendingOps.ops.length := by
  simp only [State.clearOp]
  exact List.length_filter_le _ _

end Proofs
end Kroopt.Core
