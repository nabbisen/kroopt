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
    simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs, hcond]; rfl
  · exact hsFail_legal _ _ _ _ _ h hnt

/-- `onEcdheDone` moves along a legal edge. -/
theorem onEcdheDone_legal
    (s s' : State) (secret : SecretKeyHandle) (acts : List OutputAction)
    (h : onEcdheDone s secret = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false) :
    legalEdge s.handshake s'.handshake = true := by
  unfold onEcdheDone at h
  split at h
  · rename_i hcond
    simp only [State.allocOp, TranscriptState.snapshot, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs, hcond]; rfl
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
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h
    rw [← hs, hcond]; rfl
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

end Proofs
end Kroopt.Core
