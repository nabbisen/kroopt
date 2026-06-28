import Kroopt.Core.Step
import Kroopt.Core.Alert

/-!
# Kroopt.Proofs.Closure

Terminal- and alert-policy proofs (RFC 013 §11):

* `failAlert` emits no application plaintext and no ordinary transport write —
  the optional fatal alert is the only thing it sends (`failAlert_no_emit`,
  `failAlert_no_accept`, `failAlert_only_alert_write`);
* the per-mode close path emits no application plaintext (`appClose_no_emit`);
* the centralized alert mapping never turns an error into the benign
  `closeNotify`, and error alerts are always fatal (`alertForParseError_*`,
  `alertForProtocolError_fatal_unless_close`).

These complement the M0 action-discipline theorems (terminal states absorbing,
no early plaintext) to give the full "nothing escapes after failure/close" story.
-/

namespace Kroopt.Core.Proofs

open Kroopt Kroopt.Core

/-- `allocOpOrFail` as a plain budget `if` (private copy for the close-path proofs). -/
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

/-- **No plaintext on the fatal path.** `failAlert` emits no application
plaintext (RFC 013 §7, §11). -/
theorem failAlert_no_emit (s : State) (a : AlertDescription) (e : TlsError)
    (s' : State) (acts : List OutputAction) (h : failAlert s a e = .ok (s', acts))
    (c : ConnId) (b : ByteArray) (hmem : OutputAction.emitPlaintext c b ∈ acts) : False := by
  unfold failAlert at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  rw [← h.2] at hmem
  simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
    reduceCtorEq, or_self, or_false] at hmem

/-- `failAlert` accepts no application plaintext (RFC 013 §7). -/
theorem failAlert_no_accept (s : State) (a : AlertDescription) (e : TlsError)
    (s' : State) (acts : List OutputAction) (h : failAlert s a e = .ok (s', acts))
    (c : ConnId) (n : Nat) (hmem : OutputAction.acceptPlaintextBytes c n ∈ acts) : False := by
  unfold failAlert at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  rw [← h.2] at hmem
  simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
    reduceCtorEq, or_self, or_false] at hmem

/-- **The fatal alert is the only post-failure transport write.** `failAlert`
emits no ordinary `writeTransport`; its only wire effect is the alert itself
(RFC 013 §7, §11). -/
theorem failAlert_only_alert_write (s : State) (a : AlertDescription) (e : TlsError)
    (s' : State) (acts : List OutputAction) (h : failAlert s a e = .ok (s', acts))
    (c : ConnId) (b : ByteArray) (hmem : OutputAction.writeTransport c b ∈ acts) : False := by
  unfold failAlert at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  rw [← h.2] at hmem
  simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
    reduceCtorEq, or_self, or_false] at hmem

/-- **Encoder round-trip (RFC 041 obligation 4).** The on-wire description byte decodes back to the
same alert: `ofByte (toByte a) = some a` for every description kroopt produces. This is the acceptance
proof for the `AlertDescription.toByte` encoder that puts a fatal alert on the wire. -/
theorem ofByte_toByte (a : AlertDescription) : AlertDescription.ofByte a.toByte = some a := by
  cases a <;> rfl

/-- **The fatal path transmits the alert (RFC 041 obligation 1).** `failAlert` emits a `writeAlert`
action for the same description — the alert record the interpreter frames onto the wire. Together with
`failAlert_only_alert_write` (no *ordinary* `writeTransport`), this pins the alert record as the one and
only wire effect of a fatal failure. -/
theorem failAlert_emits_alert (s : State) (a : AlertDescription) (e : TlsError)
    (s' : State) (acts : List OutputAction) (h : failAlert s a e = .ok (s', acts)) :
    OutputAction.writeAlert s.connId s.writeEpoch.epoch s.writeEpoch.seq.value a ∈ acts := by
  unfold failAlert at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  rw [← h.2]
  exact List.mem_cons_self _ _

/-- **No plaintext on the close path.** Beginning a close (any mode) emits no
application plaintext (RFC 013 §7). -/
theorem appClose_no_emit (s s' : State) (conn : ConnId) (mode : CloseMode)
    (acts : List OutputAction)
    (hnt : s.handshake.isTerminal = false)
    (h : step s (.appClose conn mode) = .ok (s', acts))
    (c : ConnId) (b : ByteArray) (hmem : OutputAction.emitPlaintext c b ∈ acts) : False := by
  unfold step at h
  split at h
  · rename_i hc; rw [hc] at hnt; simp at hnt
  · simp only [] at h
    split at h
    · split at h
      · split at h
        · split at h
          · simp only [failAlert, Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.2] at hmem
            simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
              reduceCtorEq, or_self, or_false] at hmem
          · simp only [allocOpOrFail_eq] at h
            split at h
            · unfold hsFail at h
              simp only [Except.ok.injEq, Prod.mk.injEq] at h
              rw [← h.2] at hmem
              simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
                reduceCtorEq, or_self, or_false] at hmem
            simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
          reduceCtorEq, or_self, or_false] at hmem
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2] at hmem; simp only [List.mem_singleton, reduceCtorEq] at hmem

/-- Every parse-error alert is fatal — never the benign `closeNotify`
(RFC 013 §4, §9). -/
theorem alertForParseError_is_fatal (e : ParseError) :
    alertLevel (alertForParseError e) = .fatal := by
  cases e <;> rfl

/-- A parse error never maps to `closeNotify`, so a malformed input can never be
mistaken by the peer for a clean close. -/
theorem alertForParseError_not_closeNotify (e : ParseError) :
    alertForParseError e ≠ .closeNotify := by
  cases e <;> decide

/-- Every resource-budget exhaustion alert is fatal — budget exhaustion is a
security failure, never a benign close (RFC 013 §4; RFC 037 §4). -/
theorem alertForResourceLimit_is_fatal (e : Kroopt.ResourceLimitError) :
    alertLevel (alertForResourceLimit e) = .fatal := by
  cases e <;> rfl

/-- A resource-budget exhaustion never maps to `closeNotify`. -/
theorem alertForResourceLimit_not_closeNotify (e : Kroopt.ResourceLimitError) :
    alertForResourceLimit e ≠ .closeNotify := by
  cases e <;> decide

/-- A protocol error is fatal unless it is precisely "peer sent close_notify",
which is the one benign case (RFC 013 §4). -/
theorem alertForProtocolError_fatal_unless_close (e : ProtocolError)
    (hne : e ≠ .closeNotifyReceived) :
    alertLevel (alertForProtocolError e) = .fatal := by
  cases e <;> first | rfl | exact absurd rfl hne

end Kroopt.Core.Proofs
