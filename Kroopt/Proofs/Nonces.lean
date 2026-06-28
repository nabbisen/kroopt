import Kroopt.Core.Step
import Kroopt.Core.Nonce
import Kroopt.Proofs.RecordPath

/-!
# Kroopt.Proofs.Nonces

Sequence-number and nonce safety (RFC 005 §7.1–7.3). AEAD nonce reuse is
catastrophic, so these are proof targets, not tested conventions:

* a successful seal/open advances that direction's sequence by exactly one;
* a sequence at the `UInt64` ceiling forces failure before any crypto is
  requested with a wrapped value (no silent wrap);
* for a fixed key epoch and IV base, distinct sequence numbers give distinct
  nonces.

All proofs are `sorry`/`axiom`/`unsafe`-free.
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- `allocOpOrFail` as a plain budget `if` (private copy for the nonce/seq proofs). -/
private theorem allocOpOrFail_eq (s : State) (kind : CryptoOpKind) (epoch : Epoch)
    (dir : Option Direction) (k : OperationId → State → HsResult) :
    allocOpOrFail s kind epoch dir k =
      if s.pendingOps.ops.length ≥ s.serverConfig.limits.maxPendingCryptoOps then
        hsFail s (alertForResourceLimit .pendingCryptoOps) (.resourceLimit .pendingCryptoOps)
      else
        k ⟨s.nextOpId⟩
          { s with nextOpId := s.nextOpId + 1
                   pendingOps := ⟨⟨⟨s.nextOpId⟩, kind, epoch, dir⟩ :: s.pendingOps.ops⟩ } := by
  unfold allocOpOrFail State.allocOp
  by_cases hc : s.pendingOps.ops.length ≥ s.serverConfig.limits.maxPendingCryptoOps
  · simp only [if_pos hc]
  · simp only [if_neg hc]

/-- **Nonce uniqueness within an epoch (RFC 005 §7.3).** For a fixed IV-base
identity, two sequence numbers with different values derive different nonces.
Because the concrete derivation `iv_base XOR left_pad(seq)` is a bijection in the
sequence for a fixed IV base, this is exactly the property that rules out nonce
reuse within a key epoch. -/
theorem nonce_unique_within_epoch (ivBaseId : Nat) (s1 s2 : SeqNo)
    (hne : s1.value ≠ s2.value) :
    deriveNonce ivBaseId s1 ≠ deriveNonce ivBaseId s2 := by
  intro h
  apply hne
  have := congrArg RecordNonce.seqValue h
  simpa [deriveNonce] using this

/-- **Seal step: register-and-advance, or fail closed (RFC 005 §7.1, RFC 037 §4.1).**

Crypto-op budget enforcement (RFC 037 §4.1) means an `Except.ok` from `handleAppSend` no
longer implies "the record was accepted". If the AEAD-seal op cannot be registered (the
pending-op budget is exhausted) — or the write sequence has already overflowed — the
handler returns a fatal-close result instead. The honest invariant is therefore
disjunctive:

* **registered:** the write sequence advances by exactly one and a seal `callCrypto` is
  emitted (its metadata captured `writeMeta s`, i.e. the pre-advance sequence); or
* **fail-closed:** the connection is terminal, no crypto op / plaintext crosses the
  boundary, and the sequence is unchanged.

Nonce uniqueness is preserved either way: the fail-closed branch emits no record, so it
cannot reuse an `(epoch, direction, seq)` nonce. The advance is genuinely conditional on
the op being *registered*, not on the function returning `ok`. -/
theorem seal_step_either_registers_and_advances_or_fails_closed
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts)) :
    (s'.writeEpoch.seq.value = s.writeEpoch.seq.value + 1
      ∧ ∃ c oid meta aad inner, OutputAction.callCrypto c oid (.aeadSeal meta aad inner) ∈ acts)
    ∨ (s'.writeEpoch.seq.value = s.writeEpoch.seq.value
      ∧ s'.handshake.isTerminal = true
      ∧ (∀ c oid o, OutputAction.callCrypto c oid o ∉ acts)
      ∧ (∀ c bb, OutputAction.emitPlaintext c bb ∉ acts)
      ∧ (∀ c n, OutputAction.acceptPlaintextBytes c n ∉ acts)) := by
  unfold handleAppSend recordFailAlert at h
  split at h
  · -- write-sequence overflow (next = none): fail closed, sequence unchanged
    right
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, ha⟩ := h
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · rw [← hs]
    · rw [← hs]; rfl
    · intro c oid o hin; rw [← ha] at hin
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq, or_self, or_false] at hin
    · intro c bb hin; rw [← ha] at hin
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq, or_self, or_false] at hin
    · intro c n hin; rw [← ha] at hin
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq, or_self, or_false] at hin
  · rename_i sq hsome
    simp only [allocOpOrFail_eq] at h
    split at h
    · -- crypto-op budget exhausted: fail closed, sequence unchanged
      right
      unfold hsFail at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, ha⟩ := h
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · rw [← hs]
      · rw [← hs]; rfl
      · intro c oid o hin; rw [← ha] at hin
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq, or_self, or_false] at hin
      · intro c bb hin; rw [← ha] at hin
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq, or_self, or_false] at hin
      · intro c n hin; rw [← ha] at hin
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq, or_self, or_false] at hin
    · -- registered: the seal op is emitted and the write sequence advances by one
      left
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, ha⟩ := h
      refine ⟨?_, ?_⟩
      · rw [← hs]; exact SeqNo.next_some_succ hsome
      · rw [← ha]; exact ⟨_, _, _, _, _, List.mem_cons_self _ _⟩

/-- Convenience (registered branch): a seal that actually emits its AEAD-seal op advances
the write sequence by exactly one. -/
theorem successful_registered_seal_increments_write_seq
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts))
    (hreg : ∃ c oid meta aad inner,
      OutputAction.callCrypto c oid (.aeadSeal meta aad inner) ∈ acts) :
    s'.writeEpoch.seq.value = s.writeEpoch.seq.value + 1 := by
  rcases seal_step_either_registers_and_advances_or_fails_closed s s' b acts h with
    ⟨hadv, -⟩ | ⟨-, -, hnc, -, -⟩
  · exact hadv
  · obtain ⟨c, oid, meta, aad, inner, hin⟩ := hreg
    exact absurd hin (hnc c oid _)

/-- Convenience (fail-closed branch): a seal that does *not* register its op (budget
exhausted or sequence overflow) advances nothing and lets no plaintext cross. -/
theorem budget_failed_seal_does_not_advance_write_seq
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts))
    (hnoreg : ¬ ∃ c oid meta aad inner,
      OutputAction.callCrypto c oid (.aeadSeal meta aad inner) ∈ acts) :
    s'.writeEpoch.seq.value = s.writeEpoch.seq.value
    ∧ (∀ c bb, OutputAction.emitPlaintext c bb ∉ acts)
    ∧ (∀ c n, OutputAction.acceptPlaintextBytes c n ∉ acts) := by
  rcases seal_step_either_registers_and_advances_or_fails_closed s s' b acts h with
    ⟨-, hreg⟩ | ⟨hseq, -, -, hne, hna⟩
  · exact absurd hreg hnoreg
  · exact ⟨hseq, hne, hna⟩

/-- **A successful open advances the read sequence by one (RFC 005 §7.1).** When handling
an `aeadOpened` result buffers application content, the read sequence moves up by exactly
one.

Note the asymmetry with the seal path (RFC 037 §4.1): the read sequence advances *here*,
on the authenticated open **result** (`handleCryptoResult`), which performs no allocation —
so this advance is unconditional on a successful authenticated open and needs no disjunctive
treatment. The budget gate sits one step earlier, at *registration* of the inbound
AEAD-open op in `handleTransportBytes`; its fail-closed safety (no plaintext, fatal close,
no op registered) is carried by `handleTransportBytes_no_emit` / `…_no_accept` and the
read-direction metadata by `KeySeparation.aeadOpen_uses_read_keys`. -/
theorem successful_open_increments_read_seq
    (s s' : State) (op : OperationId) (pt : ByteArray) (acts : List OutputAction)
    (h : handleCryptoResult s op (.aeadOpened pt) = .ok (s', acts))
    (b : ByteArray) (hb : s'.pendingPlainOut = some b)
    (hne : s.pendingPlainOut ≠ some b) :
    s'.readEpoch.seq.value = s.readEpoch.seq.value + 1 := by
  unfold handleCryptoResult handleCryptoResultCorrelated onInboundAlert recordFailAlert at h
  simp only [] at h
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
    | (-- not-connected handshake leaf: routes to the handshake model, never buffers
       -- application plaintext, so hb/hne are contradictory here
       cases handshakeOnPlaintextRecord_pp _ _ _ _ h with
       | inl hpp => rw [hpp] at hb; exact absurd hb hne
       | inr hpp => rw [hpp] at hb; simp only [reduceCtorEq] at hb)
    | (-- stale-guard else leaf: s' = s, so the buffer is unchanged, contradicting hne
       simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨hs, -⟩ := h
       rw [← hs] at hb
       exact absurd hb hne)
    | (rename_i hsome
       simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨hs, -⟩ := h
       rw [← hs] at hb ⊢
       simp only [State.clearOp] at hb ⊢
       first
       | (exact SeqNo.next_some_succ hsome)
       | (exact absurd hb hne)
       | (simp only [reduceCtorEq] at hb))
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨hs, -⟩ := h
       rw [← hs] at hb
       simp only [State.clearOp] at hb
       first | (exact absurd hb hne) | (simp only [reduceCtorEq] at hb)))

/-- **No silent wrap (RFC 005 §7.2).** If the write sequence is at the ceiling,
a send requests no crypto and fails — no seal is emitted with a wrapped
sequence value. -/
theorem no_crypto_on_write_seq_overflow
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts))
    (hov : s.writeEpoch.seq.next = none) :
    (∀ (c : ConnId) (oid : OperationId) (op : CryptoOp),
        OutputAction.callCrypto c oid op ∉ acts)
    ∧ s'.handshake.isTerminal = true := by
  unfold handleAppSend recordFailAlert at h
  simp only [hov] at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨hs, ha⟩ := h
  refine ⟨?_, ?_⟩
  · intro c oid op hmem
    rw [← ha] at hmem
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
      reduceCtorEq, or_self, or_false] at hmem
  · rw [← hs]; rfl

end Proofs
end Kroopt.Core
