import Kroopt.Core.Step
import Kroopt.Proofs.RecordPath

/-!
# Kroopt.Proofs.KeySeparation

Directional and epoch key separation (RFC 005 §7.4, §7.5). A read operation must
use only read keys and a write operation only write keys; handshake records use
handshake-epoch keys and application records application-epoch keys. The core
must never emit a `callCrypto` whose key direction or epoch is inconsistent with
the operation.

These are proved structurally over the record path: the only seal request carries
`writeMeta` (write direction, application epoch) and the only open request carries
`readMeta` (read direction, application epoch). Handshake-epoch operations arrive
with the handshake model at M4.

All proofs are `sorry`/`axiom`/`unsafe`-free.
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- `allocOpOrFail` as a plain budget `if` (private copy for this proof file). -/
private theorem allocOpOrFail_eq (s : State) (kind : CryptoOpKind) (epoch : Epoch)
    (dir : Option Direction) (k : OperationId → State → HsResult) :
    allocOpOrFail s kind epoch dir k =
      if s.pendingOps.ops.length ≥ ResourceLimits.standard.maxPendingCryptoOps then
        hsFail s (alertForResourceLimit .pendingCryptoOps) (.resourceLimit .pendingCryptoOps)
      else
        k ⟨s.nextOpId⟩
          { s with nextOpId := s.nextOpId + 1
                   pendingOps := ⟨⟨⟨s.nextOpId⟩, kind, epoch, dir⟩ :: s.pendingOps.ops⟩ } := by
  unfold allocOpOrFail State.allocOp
  by_cases hc : s.pendingOps.ops.length ≥ ResourceLimits.standard.maxPendingCryptoOps
  · simp only [if_pos hc]
  · simp only [if_neg hc]

/-- **Directional + epoch separation for seals (RFC 005 §7.4, §7.5).** Any AEAD
seal a send requests carries write-direction, application-epoch metadata. -/
theorem aeadSeal_uses_write_keys
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta)
    (aad pt : ByteArray)
    (hmem : OutputAction.callCrypto c oid (CryptoOp.aeadSeal meta aad pt) ∈ acts) :
    meta.direction = .write ∧ meta.epoch = .application := by
  unfold handleAppSend recordFailAlert at h
  split at h
  · -- overflow: acts = [failWithAlert, reportError], no callCrypto
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, ha⟩ := h
    rw [← ha] at hmem
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
      reduceCtorEq, or_self, or_false] at hmem
  · -- registered seal carries write metadata; on budget overflow no callCrypto is emitted
    simp only [allocOpOrFail_eq] at h
    split at h
    · -- budget-failed: acts = [failWithAlert, reportError], membership is vacuous
      unfold hsFail at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, ha⟩ := h
      rw [← ha] at hmem
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
        reduceCtorEq, or_self, or_false] at hmem
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, ha⟩ := h
    rw [← ha] at hmem
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_false, or_self, OutputAction.callCrypto.injEq, CryptoOp.aeadSeal.injEq] at hmem
    obtain ⟨-, -, hmeta, -, -⟩ := hmem
    rw [hmeta]
    exact ⟨rfl, rfl⟩

/-- **Directional + epoch separation for opens (RFC 005 §7.4, §7.5).** Any AEAD
open a received record requests carries read-direction metadata at the connection's
current read epoch — `handshake` while opening the protected client Finished before
`connected`, `application` afterwards. It is never a write key, and never an epoch
other than the installed read epoch. -/
theorem aeadOpen_uses_read_keys
    (s s' : State) (bytes : ByteArray) (acts : List OutputAction)
    (h : handleTransportBytes s bytes = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta)
    (aad ct : ByteArray)
    (hmem : OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∈ acts) :
    meta.direction = .read ∧ meta.epoch = s.readEpoch.epoch := by
  unfold handleTransportBytes onInboundAlert recordFailAlert at h
  simp only [] at h
  try simp only [allocOpOrFail_eq] at h
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (
    first
    | exact absurd hmem (handshakeOnPlaintextRecord_no_aeadOpen _ _ _ _ h c oid meta aad ct)
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, ha⟩ := h
       rw [← ha] at hmem
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_false, or_self, OutputAction.callCrypto.injEq, CryptoOp.aeadOpen.injEq] at hmem
       obtain ⟨-, -, hmeta, -, -⟩ := hmem
       rw [hmeta]
       exact ⟨rfl, rfl⟩)
    | (try unfold hsFail at h
       simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, ha⟩ := h
       rw [← ha] at hmem
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
         reduceCtorEq, or_self, or_false] at hmem))

end Proofs
end Kroopt.Core
