import Kroopt.Proofs.Basic

/-!
# Kroopt.Proofs.ActionDiscipline

The action-discipline safety theorems (RFC 002 §7, RFC 015 §15.1, RFC 022 §7).

The headline guarantee a dependent such as jemmet relies on is **no early
plaintext**: the core never emits application plaintext (`emitPlaintext`) or
accepts application plaintext (`acceptPlaintextBytes`) unless it is `connected`.
These theorems are proved over the real `step`, so they constrain every future
milestone's transitions: any new transition that emits plaintext outside
`connected` would break the proof (RFC 022 §7).
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
  unfold step at h
  split at h
  · -- terminal phase: acts = [], so membership is impossible
    simp only [absorbTerminal, Except.ok.injEq, Prod.mk.injEq] at h
    rw [← h.2] at hmem
    simp at hmem
  · -- non-terminal: case on the event
    split at h
    · -- appRecvRequested
      split at h
      · -- connected: the only branch that can emit plaintext
        rename_i hconn
        exact hconn
      · -- not connected: returns (s, []) directly, no inner match
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem
        simp at hmem
    · -- appSend
      split at h
      · -- connected: acts = []
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem
        simp at hmem
      · -- not connected: failAlert, no emit
        simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hmem
        rcases hmem with hmem | hmem <;>
          · subst hmem
            simp [OutputAction.isPlaintextEmit] at hpe
    · -- appClose
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_singleton] at hmem
      subst hmem
      simp [OutputAction.isPlaintextEmit] at hpe
    · -- transportEof
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_singleton] at hmem
      subst hmem
      simp [OutputAction.isPlaintextEmit] at hpe
    · -- timeout
      simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hmem
      rcases hmem with hmem | hmem <;>
        · subst hmem
          simp [OutputAction.isPlaintextEmit] at hpe
    · -- catch-all placeholder events: acts = []
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem
      simp at hmem

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
