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

/-- **A successful seal advances the write sequence by one (RFC 005 §7.1).** -/
theorem successful_seal_increments_write_seq
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts))
    (hsucc : s.writeEpoch.seq.next ≠ none) :
    s'.writeEpoch.seq.value = s.writeEpoch.seq.value + 1 := by
  unfold handleAppSend recordFailAlert at h
  split at h
  · rename_i hnone; exact absurd hnone hsucc
  · rename_i sq hsome
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs]
    simp only [State.allocOp]
    exact SeqNo.next_some_succ hsome

/-- **A successful open advances the read sequence by one (RFC 005 §7.1).** When
handling an `aeadOpened` result buffers application content, the read sequence
moves up by exactly one. -/
theorem successful_open_increments_read_seq
    (s s' : State) (op : OperationId) (pt : ByteArray) (acts : List OutputAction)
    (h : handleCryptoResult s op (.aeadOpened pt) = .ok (s', acts))
    (b : ByteArray) (hb : s'.pendingPlainOut = some b)
    (hne : s.pendingPlainOut ≠ some b) :
    s'.readEpoch.seq.value = s.readEpoch.seq.value + 1 := by
  unfold handleCryptoResult handleCryptoResultCorrelated recordFailAlert at h
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
