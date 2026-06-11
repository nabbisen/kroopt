import Kroopt.Proofs.Basic
import Kroopt.Proofs.RecordPath

/-!
# Kroopt.Proofs.ActionDiscipline

The action-discipline safety theorems (RFC 002 §7, RFC 015 §15.1, RFC 022 §7).

The headline guarantee a dependent such as jemmet relies on is **no early
plaintext**: the core never emits application plaintext (`emitPlaintext`) or
accepts application plaintext (`acceptPlaintextBytes`) unless it is `connected`.
These theorems are proved over the real `step`, so they constrain every future
milestone's transitions: the M2 record path added inbound/outbound transitions,
and the proof still holds precisely because every plaintext emission flows
through the single `connected`-gated `appRecvRequested` site and the record
handlers provably emit none (`Kroopt.Proofs.RecordPath`).
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- **No early plaintext (emit).** If a step emits any `emitPlaintext` action,
the connection was `connected` (RFC 002 §7, RFC 015 §15.1). -/
theorem no_plaintext_emit_unless_connected
    (s s' : State) (ev : InputEvent) (acts : List OutputAction)
    (h : step s ev = .ok (s', acts))
    (a : OutputAction) (hmem : a ∈ acts) (hpe : a.isPlaintextEmit = true) :
    s.handshake.isConnected = true := by
  -- `a` is literally an `emitPlaintext`.
  obtain ⟨ec, eb, rfl⟩ := OutputAction.isPlaintextEmit_eq_true hpe
  unfold step at h
  split at h
  · -- terminal phase: acts = [], so membership is impossible
    simp only [absorbTerminal, Except.ok.injEq, Prod.mk.injEq] at h
    rw [← h.2] at hmem; simp at hmem
  · -- non-terminal: case on the event (ten arms, in `step` order)
    split at h
    · -- appRecvRequested
      split at h
      · rename_i hconn; exact hconn         -- connected: the sole emitter
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem; simp at hmem
    · -- appSend
      split at h
      · exact absurd hmem (handleAppSend_no_plaintext h)   -- connected: handler, no emit
      · simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
          reduceCtorEq, or_self, or_false] at hmem
    · -- appClose: [closeTransport]
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_singleton, reduceCtorEq] at hmem
    · -- transportEof: [reportError]
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_singleton, reduceCtorEq] at hmem
    · -- timeout: failAlert
      simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
        reduceCtorEq, or_self, or_false] at hmem
    · -- transportBytes: record read path, no emit
      exact absurd hmem (handleTransportBytes_no_plaintext h)
    · -- cryptoResult: record/handshake result path, no emit
      exact absurd hmem (handleCryptoResult_no_plaintext h)
    · -- transportReadable: [readTransport]
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_singleton, reduceCtorEq] at hmem
    · -- transportWritable: []
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp at hmem
    · -- appFlush: []
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp at hmem

/-- **No early plaintext (accept).** If a step accepts application plaintext from
the application (`acceptPlaintextBytes`), the connection was `connected`
(RFC 002 §7, RFC 004 §9). The only producer is the connected send path. -/
theorem accept_plaintext_only_connected
    (s s' : State) (ev : InputEvent) (acts : List OutputAction)
    (h : step s ev = .ok (s', acts))
    (c : ConnId) (n : Nat) (hmem : OutputAction.acceptPlaintextBytes c n ∈ acts) :
    s.handshake.isConnected = true := by
  unfold step at h
  split at h
  · simp only [absorbTerminal, Except.ok.injEq, Prod.mk.injEq] at h
    rw [← h.2] at hmem; simp at hmem
  · split at h
    · -- appRecvRequested
      split at h
      · rename_i hconn; exact hconn
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem; simp at hmem
    · -- appSend
      split at h
      · rename_i hconn; exact hconn          -- connected handler is the only accept site
      · simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
          reduceCtorEq, or_self, or_false] at hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem
    · simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
        reduceCtorEq, or_self, or_false] at hmem
    · -- transportBytes: handler emits no acceptPlaintextBytes
      exact absurd hmem (handleTransportBytes_no_accept h)
    · -- cryptoResult
      exact absurd hmem (handleCryptoResult_no_accept h)
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp at hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp at hmem

/-- **No plaintext after terminal.** A terminal connection emits no plaintext,
because it emits no actions at all (corollary of `terminal_absorbing`;
RFC 013 §7, RFC 015 §15.1). -/
theorem no_plaintext_after_terminal
    (s s' : State) (ev : InputEvent) (acts : List OutputAction)
    (ht : s.handshake.isTerminal = true)
    (h : step s ev = .ok (s', acts)) :
    ∀ a ∈ acts, a.isPlaintextEmit = false := by
  have habs := terminal_absorbing s s' ev acts ht h
  intro a ha
  rw [habs.2] at ha
  simp at ha

end Proofs
end Kroopt.Core
