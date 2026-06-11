import Kroopt.Core.Step

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
  · -- success: the sole callCrypto carries `writeMeta s`
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, ha⟩ := h
    rw [← ha] at hmem
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_false, or_self, OutputAction.callCrypto.injEq, CryptoOp.aeadSeal.injEq] at hmem
    obtain ⟨-, -, hmeta, -, -⟩ := hmem
    rw [hmeta]
    exact ⟨rfl, rfl⟩

/-- **Directional + epoch separation for opens (RFC 005 §7.4, §7.5).** Any AEAD
open a received record requests carries read-direction, application-epoch
metadata. -/
theorem aeadOpen_uses_read_keys
    (s s' : State) (bytes : ByteArray) (acts : List OutputAction)
    (h : handleTransportBytes s bytes = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta)
    (aad ct : ByteArray)
    (hmem : OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∈ acts) :
    meta.direction = .read ∧ meta.epoch = .application := by
  unfold handleTransportBytes recordFailAlert at h
  simp only [] at h
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
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, ha⟩ := h
       rw [← ha] at hmem
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_false, or_self, OutputAction.callCrypto.injEq, CryptoOp.aeadOpen.injEq] at hmem
       obtain ⟨-, -, hmeta, -, -⟩ := hmem
       rw [hmeta]
       exact ⟨rfl, rfl⟩)
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, ha⟩ := h
       rw [← ha] at hmem
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
         reduceCtorEq, or_self, or_false] at hmem))

end Proofs
end Kroopt.Core
