import Kroopt.Core.Handshake

/-!
# Kroopt.Proofs.Handshake

Handshake-model safety (RFC 006 §9). Three guarantees:

* **Legal transitions.** Every handshake transition moves the phase along a
  `legalEdge` — no skipped or out-of-order phases.
* **Finished before connected.** The only transition that reaches `connected`
  does so from `requestedClientFinishedVerify` and only when the client Finished
  verified. So application data (permitted only in `connected`) is unreachable
  until the client Finished is checked.
* **No plaintext during the handshake.** No handshake transition emits
  `emitPlaintext`.

All proofs are `sorry`/`axiom`/`unsafe`-free.
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- Helper: a handshake transition that ends in `hsFail` lands on a `legalEdge`
from any non-terminal phase (clean failure). -/
private theorem hsFail_legal (s : State) (a : AlertDescription) (e : TlsError)
    (s' : State) (acts : List OutputAction)
    (h : hsFail s a e = .ok (s', acts)) (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold hsFail at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨hs, -⟩ := h
  rw [← hs]
  unfold legalEdge
  simp [hnt]

/-- `onClientHello` moves along a legal edge (RFC 006 §9). -/
theorem onClientHello_legal
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : onClientHello s vch w = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onClientHello at h
  split at h
  · rename_i hcond
    split at h
    · exact hsFail_legal _ _ _ _ _ h hnt
    · simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, -⟩ := h
      rw [← hs, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onEcdheDone` moves along a legal edge. -/
theorem onEcdheDone_legal
    (s s' : State) (serverShare : ByteArray) (secret : SecretKeyHandle) (acts : List OutputAction)
    (h : onEcdheDone s serverShare secret = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onEcdheDone at h
  split at h
  · rename_i hcond
    simp only [State.allocOp, TranscriptState.snapshot, KeyScheduleDriver.startPostEcdhe,
      Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onHsScheduleResult` moves along a legal edge: it either self-loops in
`derivedHandshakeSecrets` (pumping the schedule), advances to
`requestedCertificateVerifySignature` (stage done), or fails. -/
theorem onHsScheduleResult_legal
    (s s' : State) (r : CryptoResult) (acts : List OutputAction)
    (h : onHsScheduleResult s r = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onHsScheduleResult at h
  split at h
  · rename_i hcond
    split at h
    · exact hsFail_legal _ _ _ _ _ h hnt
    · split at h
      · exact hsFail_legal _ _ _ _ _ h hnt
      · simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨hs, -⟩ := h
        have hsh : s'.handshake = s.handshake := by rw [← hs]
        rw [hsh, hcond]; rfl
      · split at h
        · simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq,
            Prod.mk.injEq] at h
          obtain ⟨hs, -⟩ := h
          have hsh : s'.handshake = .requestedCertificateVerifySignature := by rw [← hs]
          rw [hsh, hcond]; rfl
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨hs, -⟩ := h
          have hsh : s'.handshake = s.handshake := by rw [← hs]
          rw [hsh, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onCertVerifySigned` moves along a legal edge. -/
theorem onCertVerifySigned_legal
    (s s' : State) (sig : ByteArray) (acts : List OutputAction)
    (h : onCertVerifySigned s sig = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onCertVerifySigned at h
  split at h
  · rename_i hcond
    simp only [TranscriptState.snapshot, State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onServerFinishedMac` moves along a legal edge: it advances
`requestedServerFinishedMac → sentCertificateVerify`, or fails. -/
theorem onServerFinishedMac_legal
    (s s' : State) (vd : ByteArray) (acts : List OutputAction)
    (h : onServerFinishedMac s vd = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onServerFinishedMac at h
  split at h
  · rename_i hcond
    split at h
    · exact hsFail_legal _ _ _ _ _ h hnt
    · simp only [TranscriptState.snapshot] at h
      split at h
      · exact hsFail_legal _ _ _ _ _ h hnt
      · simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨hs, -⟩ := h
        rw [← hs, hcond]; rfl
      · exact hsFail_legal _ _ _ _ _ h hnt
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onApScheduleResult` moves along a legal edge: it either self-loops in
`sentCertificateVerify` (pumping the application-key stage) or advances to
`sentServerFinished` (stage complete), or fails. -/
theorem onApScheduleResult_legal
    (s s' : State) (r : CryptoResult) (acts : List OutputAction)
    (h : onApScheduleResult s r = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onApScheduleResult at h
  split at h
  · rename_i hcond
    split at h
    · exact hsFail_legal _ _ _ _ _ h hnt
    · split at h
      · exact hsFail_legal _ _ _ _ _ h hnt
      · simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨hs, -⟩ := h
        have hsh : s'.handshake = s.handshake := by rw [← hs]
        rw [hsh, hcond]; rfl
      · split at h
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨hs, -⟩ := h
          have hsh : s'.handshake = .sentServerFinished := by rw [← hs]
          rw [hsh, hcond]; rfl
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨hs, -⟩ := h
          have hsh : s'.handshake = s.handshake := by rw [← hs]
          rw [hsh, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onClientFinishedBytes` moves along a legal edge. -/
theorem onClientFinishedBytes_legal
    (s s' : State) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedBytes s cf = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onClientFinishedBytes at h
  split at h
  · rename_i hcond
    simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onClientFinishedVerified` moves along a legal edge. -/
theorem onClientFinishedVerified_legal
    (s s' : State) (verified : Bool) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedVerified s verified cf = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onClientFinishedVerified at h
  split at h
  · rename_i hcond
    split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, -⟩ := h
      rw [← hs, hcond]; rfl
    · exact hsFail_legal _ _ _ _ _ h hnt
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- **Client Finished verified before connected (RFC 006 §9).** The only
transition reaching `connected` requires the client-Finished verification to have
succeeded. Since application data is permitted only in `connected`, no
application data flows before the client Finished is checked. -/
theorem connected_requires_finished_verified
    (s s' : State) (verified : Bool) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedVerified s verified cf = .ok (s', acts))
    (hc : s'.handshake = .connected) :
    verified = true ∧ s.handshake = .requestedClientFinishedVerify := by
  unfold onClientFinishedVerified hsFail at h
  split at h
  · rename_i hcond
    split at h
    · rename_i hv
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, -⟩ := h
      exact ⟨hv, hcond⟩
    · -- verification failed ⇒ failed phase, contradicting `connected`
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, -⟩ := h
      rw [← hs] at hc; simp only [reduceCtorEq] at hc
  · -- wrong phase ⇒ failed, contradicting `connected`
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs] at hc; simp only [reduceCtorEq] at hc

/-! ## Handshake transitions emit no application plaintext

These feed the record-handler no-emit/no-accept proofs once the handshake is
wired into the live handlers (M5): every handshake transition emits only
`callCrypto` / `writeTransport` / `reportHandshakeComplete` / `failWithAlert` /
`reportError`, never `emitPlaintext` or `acceptPlaintextBytes`. -/

/-- Tactic-shared refutation: after reducing a handshake transition to its
concrete action list, a plaintext-emit/accept membership is impossible. -/
private theorem hs_no_emit_onClientHello
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : onClientHello s vch w = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onClientHello hsFail at h
  split at h <;> (try split at h) <;>
    (simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onEcdheDone
    (s s' : State) (serverShare : ByteArray) (secret : SecretKeyHandle) (acts : List OutputAction)
    (h : onEcdheDone s serverShare secret = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onEcdheDone hsFail at h
  split at h <;>
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onServerRandomDone
    (s s' : State) (random : ByteArray) (acts : List OutputAction)
    (h : onServerRandomDone s random = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onServerRandomDone hsFail at h
  split at h <;>
    (simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onHsScheduleResult
    (s s' : State) (r : CryptoResult) (acts : List OutputAction)
    (h : onHsScheduleResult s r = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onHsScheduleResult hsFail at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onCertVerifySigned
    (s s' : State) (sig : ByteArray) (acts : List OutputAction)
    (h : onCertVerifySigned s sig = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onCertVerifySigned hsFail at h
  simp only [TranscriptState.snapshot] at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onServerFinishedMac
    (s s' : State) (vd : ByteArray) (acts : List OutputAction)
    (h : onServerFinishedMac s vd = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onServerFinishedMac hsFail at h
  simp only [TranscriptState.snapshot] at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onApScheduleResult
    (s s' : State) (r : CryptoResult) (acts : List OutputAction)
    (h : onApScheduleResult s r = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onApScheduleResult hsFail at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onClientFinishedBytes
    (s s' : State) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedBytes s cf = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onClientFinishedBytes hsFail at h
  split at h <;>
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_emit_onClientFinishedVerified
    (s s' : State) (v : Bool) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedVerified s v cf = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold onClientFinishedVerified hsFail at h
  split at h
  · split at h <;>
      (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false] at hmem)
  · simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_self, or_false] at hmem

/-- The gating-result dispatch emits no application plaintext. -/
theorem handshakeOnGatingResult_no_emit
    (s s' : State) (op : OperationId) (r : CryptoResult) (acts : List OutputAction)
    (h : handshakeOnGatingResult s op r = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold handshakeOnGatingResult at h
  simp only [] at h
  split at h
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (
    first
    | exact hs_no_emit_onEcdheDone _ _ _ _ _ h c bb hmem
    | exact hs_no_emit_onServerRandomDone _ _ _ _ h c bb hmem
    | exact hs_no_emit_onHsScheduleResult _ _ _ _ h c bb hmem
    | exact hs_no_emit_onApScheduleResult _ _ _ _ h c bb hmem
    | exact hs_no_emit_onCertVerifySigned _ _ _ _ h c bb hmem
    | exact hs_no_emit_onServerFinishedMac _ _ _ _ h c bb hmem
    | exact hs_no_emit_onClientFinishedVerified _ _ _ _ _ h c bb hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.not_mem_nil] at hmem))

/-- The ClientHello transition emits no application plaintext. -/
theorem handshakeOnClientHello_no_emit
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : handshakeOnClientHello s vch w = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts :=
  hs_no_emit_onClientHello s s' vch w acts h c bb

/-- The client-Finished plaintext transition emits no application plaintext. -/
theorem onClientFinishedBytes_no_emit
    (s s' : State) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedBytes s cf = .ok (s', acts)) (c : ConnId) (bb : ByteArray) :
    OutputAction.emitPlaintext c bb ∉ acts :=
  hs_no_emit_onClientFinishedBytes s s' cf acts h c bb

/-! ### …and accept no application plaintext -/

private theorem hs_no_accept_generic_onClientHello
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : onClientHello s vch w = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onClientHello hsFail at h
  split at h <;> (try split at h) <;>
    (simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onEcdheDone
    (s s' : State) (serverShare : ByteArray) (secret : SecretKeyHandle) (acts : List OutputAction)
    (h : onEcdheDone s serverShare secret = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onEcdheDone hsFail at h
  split at h <;>
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onServerRandomDone
    (s s' : State) (random : ByteArray) (acts : List OutputAction)
    (h : onServerRandomDone s random = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onServerRandomDone hsFail at h
  split at h <;>
    (simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onHsScheduleResult
    (s s' : State) (r : CryptoResult) (acts : List OutputAction)
    (h : onHsScheduleResult s r = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onHsScheduleResult hsFail at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onCertVerifySigned
    (s s' : State) (sig : ByteArray) (acts : List OutputAction)
    (h : onCertVerifySigned s sig = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onCertVerifySigned hsFail at h
  simp only [TranscriptState.snapshot] at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onServerFinishedMac
    (s s' : State) (vd : ByteArray) (acts : List OutputAction)
    (h : onServerFinishedMac s vd = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onServerFinishedMac hsFail at h
  simp only [TranscriptState.snapshot] at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onApScheduleResult
    (s s' : State) (r : CryptoResult) (acts : List OutputAction)
    (h : onApScheduleResult s r = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onApScheduleResult hsFail at h
  repeat' split at h
  all_goals
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

private theorem hs_no_accept_onClientFinishedVerified
    (s s' : State) (v : Bool) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedVerified s v cf = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onClientFinishedVerified hsFail at h
  split at h
  · split at h <;>
      (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false] at hmem)
  · simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_self, or_false] at hmem

theorem handshakeOnGatingResult_no_accept
    (s s' : State) (op : OperationId) (r : CryptoResult) (acts : List OutputAction)
    (h : handshakeOnGatingResult s op r = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold handshakeOnGatingResult at h
  simp only [] at h
  split at h
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (try split at h)
  all_goals (
    first
    | exact hs_no_accept_onEcdheDone _ _ _ _ _ h c n hmem
    | exact hs_no_accept_onServerRandomDone _ _ _ _ h c n hmem
    | exact hs_no_accept_onHsScheduleResult _ _ _ _ h c n hmem
    | exact hs_no_accept_onApScheduleResult _ _ _ _ h c n hmem
    | exact hs_no_accept_onCertVerifySigned _ _ _ _ h c n hmem
    | exact hs_no_accept_onServerFinishedMac _ _ _ _ h c n hmem
    | exact hs_no_accept_onClientFinishedVerified _ _ _ _ _ h c n hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.not_mem_nil] at hmem))

theorem handshakeOnClientHello_no_accept
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : handshakeOnClientHello s vch w = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts :=
  hs_no_accept_generic_onClientHello s s' vch w acts h c n

theorem onClientFinishedBytes_no_accept
    (s s' : State) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedBytes s cf = .ok (s', acts)) (c : ConnId) (n : Nat) :
    OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold onClientFinishedBytes hsFail at h
  split at h <;>
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false] at hmem)

/-! ### …and request no AEAD-open (the handshake never opens application records)

`aeadOpen` callCryptos come only from the connected record path; the handshake
transitions request `ecdhe` / `signCertificateVerify` / `verifyFinished`. This
feeds `KeySeparation.aeadOpen_uses_read_keys` once the handshake shares the
inbound handler. -/

private theorem hs_no_aeadOpen_onClientHello
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : onClientHello s vch w = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta) (aad ct : ByteArray) :
    OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∉ acts := by
  intro hmem
  unfold onClientHello hsFail at h
  split at h <;> (try split at h) <;>
    (simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem)

private theorem hs_no_aeadOpen_onClientFinishedBytes
    (s s' : State) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedBytes s cf = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta) (aad ct : ByteArray) :
    OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∉ acts := by
  intro hmem
  unfold onClientFinishedBytes hsFail at h
  split at h <;>
    (simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
     obtain ⟨-, rfl⟩ := h
     simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
       or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem)

/-- The plaintext-handshake-record dispatch requests no AEAD-open. -/
theorem handshakeOnClientHello_no_aeadOpen
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (h : handshakeOnClientHello s vch w = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta) (aad ct : ByteArray) :
    OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∉ acts :=
  hs_no_aeadOpen_onClientHello s s' vch w acts h c oid meta aad ct

theorem onClientFinishedBytes_no_aeadOpen
    (s s' : State) (cf : ByteArray) (acts : List OutputAction)
    (h : onClientFinishedBytes s cf = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta) (aad ct : ByteArray) :
    OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∉ acts :=
  hs_no_aeadOpen_onClientFinishedBytes s s' cf acts h c oid meta aad ct

end Proofs
end Kroopt.Core
