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

/-! ## RFC 039 §5: named-group selection is authorized

The core never negotiates a group outside the endpoint's policy, and never invents a
share the client did not send. `selectGroup_authorized` is the §5.1 capstone — any group
selection is simultaneously endpoint-allowed and client-offered — and
`ecdhe_op_matches_selected_group` (§5.2) ties the actual ECDHE crypto op to the recorded
group, so a P-256 ECDHE operation is requested only when P-256 was the selected group. -/

/-- A share found for group `g` belongs to a pair the client actually offered: `shareFor?`
returns a `find?` hit, and a hit is a member whose first component is `g` (RFC 039 §4.3). -/
private theorem shareFor?_mem {g : NamedGroup} {offered : List (NamedGroup × ByteArray)} {sh : ByteArray}
    (h : shareFor? g offered = some sh) : (g, sh) ∈ offered := by
  unfold shareFor? at h
  rw [Option.map_eq_some'] at h
  obtain ⟨p, hfind, hsnd⟩ := h
  obtain ⟨a, b⟩ := p
  simp only [] at hsnd
  have hpred := List.find?_some hfind
  simp only [] at hpred
  have hfst : a = g := of_decide_eq_true hpred
  subst hfst; subst hsnd
  exact List.mem_of_find?_eq_some hfind

/-- RFC 039 §5.1: core group selection is authorized. Whatever group `selectGroup` returns
is both in the endpoint's `allowed` policy and backed by a share the client offered. There is
no execution path on which the core picks a group outside the policy or fabricates a share —
which is precisely what makes an `[x25519]`-only endpoint refuse a secp256r1-only client. -/
theorem selectGroup_authorized {offered : List (NamedGroup × ByteArray)} {allowed : List NamedGroup}
    {g : NamedGroup} {sh : ByteArray}
    (h : selectGroup offered allowed = some (g, sh)) :
    g ∈ allowed ∧ (g, sh) ∈ offered := by
  unfold selectGroup groupPreference at h
  simp only [List.findSome?_cons, List.findSome?_nil] at h
  by_cases hc1 : NamedGroup.x25519 ∈ allowed
  · cases hsh1 : shareFor? NamedGroup.x25519 offered with
    | some s1 =>
      simp only [if_pos hc1, hsh1, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨hc1, shareFor?_mem hsh1⟩
    | none =>
      by_cases hc2 : NamedGroup.secp256r1 ∈ allowed
      · cases hsh2 : shareFor? NamedGroup.secp256r1 offered with
        | some s2 =>
          simp only [if_pos hc1, hsh1, if_pos hc2, hsh2, Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          exact ⟨hc2, shareFor?_mem hsh2⟩
        | none => simp only [if_pos hc1, hsh1, if_pos hc2, hsh2, reduceCtorEq] at h
      · simp only [if_pos hc1, hsh1, if_neg hc2, reduceCtorEq] at h
  · by_cases hc2 : NamedGroup.secp256r1 ∈ allowed
    · cases hsh2 : shareFor? NamedGroup.secp256r1 offered with
      | some s2 =>
        simp only [if_neg hc1, if_pos hc2, hsh2, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨hc2, shareFor?_mem hsh2⟩
      | none => simp only [if_neg hc1, if_pos hc2, hsh2, reduceCtorEq] at h
    · simp only [if_neg hc1, if_neg hc2, reduceCtorEq] at h

/-- RFC 039 §5.2: the ECDHE operation matches the selected group. If `onServerRandomDone`
emits a P-256 ECDHE op, then the recorded `selectedGroup` is `secp256r1` — the core never
runs a P-256 ECDH for a connection on which it negotiated a different group. -/
theorem ecdhe_op_matches_selected_group
    (s s' : State) (random : ByteArray) (acts : List OutputAction)
    (c : ConnId) (oid : OperationId) (peer : ByteArray)
    (h : onServerRandomDone s random = .ok (s', acts))
    (hmem : OutputAction.callCrypto c oid (CryptoOp.ecdheP256 peer) ∈ acts) :
    s.negotiated.selectedGroup = some .secp256r1 := by
  unfold onServerRandomDone at h
  split at h
  · simp only [State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    split at hmem
    · rename_i hsel; exact hsel
    · simp only [List.mem_cons, List.not_mem_nil, or_false, OutputAction.callCrypto.injEq,
        CryptoOp.ecdheX25519.injEq, reduceCtorEq, and_false] at hmem
  · unfold hsFail at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    simp only [List.mem_cons, List.not_mem_nil, or_false, OutputAction.callCrypto.injEq,
      reduceCtorEq, or_self] at hmem

/-- The core records only an endpoint-allowed group. When `onClientHello` succeeds into
`requestedServerRandom`, the `selectedGroup` it stored is `some g` with `g` in the resolved
endpoint's policy — the selectedGroup half of RFC 039 §5.2's non-event (a disallowed group
never reaches `selectedGroup`). -/
theorem onClientHello_selectedGroup_allowed
    (s s' : State) (vch : ValidClientHello) (w : ByteArray) (acts : List OutputAction)
    (allowed : List NamedGroup)
    (hep : (Option.map (fun e => e.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD [] = allowed)
    (h : onClientHello s vch w = .ok (s', acts))
    (hsucc : s'.handshake = .requestedServerRandom) :
    ∃ g, s'.negotiated.selectedGroup = some g ∧ g ∈ allowed := by
  unfold onClientHello at h
  split at h
  · split at h
    · unfold hsFail at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, -⟩ := h
      simp only [reduceCtorEq] at hsucc
    · split at h
      · unfold hsFail at h
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, -⟩ := h
        simp only [reduceCtorEq] at hsucc
      · cases hsel : selectGroup vch.offeredShares
            ((Option.map (fun x => x.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD []) with
        | none =>
          unfold hsFail at h
          simp only [hsel, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, -⟩ := h
          simp only [reduceCtorEq] at hsucc
        | some gp =>
          obtain ⟨selGroup, selShare⟩ := gp
          simp only [hsel, State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, -⟩ := h
          refine ⟨selGroup, rfl, ?_⟩
          have ha := (selectGroup_authorized hsel).1
          rw [hep] at ha
          exact ha
  · unfold hsFail at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, -⟩ := h
    simp only [reduceCtorEq] at hsucc

/-- RFC 039 §5.2 `no_disallowed_group_crypto_op` (the P-256 case, which is the only one the
two supported groups can violate): if secp256r1 is not in the endpoint's policy, then no
P-256 ECDHE crypto op is ever emitted on the `onClientHello → onServerRandomDone` path. The
disallowed group reaches neither `selectedGroup` (by `onClientHello_selectedGroup_allowed`)
nor a crypto op (by `ecdhe_op_matches_selected_group`). -/
theorem no_disallowed_group_crypto_op
    (s s1 s2 : State) (vch : ValidClientHello) (w random : ByteArray)
    (acts1 acts2 : List OutputAction) (allowed : List NamedGroup)
    (c : ConnId) (oid : OperationId) (peer : ByteArray)
    (hep : (Option.map (fun e => e.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD [] = allowed)
    (hch : onClientHello s vch w = .ok (s1, acts1))
    (hsucc : s1.handshake = .requestedServerRandom)
    (hsr : onServerRandomDone s1 random = .ok (s2, acts2))
    (hdis : NamedGroup.secp256r1 ∉ allowed)
    (hmem : OutputAction.callCrypto c oid (CryptoOp.ecdheP256 peer) ∈ acts2) : False := by
  have hsel := ecdhe_op_matches_selected_group s1 s2 random acts2 c oid peer hsr hmem
  obtain ⟨g, hg, hga⟩ := onClientHello_selectedGroup_allowed s s1 vch w acts1 allowed hep hch hsucc
  rw [hsel] at hg
  simp only [Option.some.injEq] at hg
  subst hg
  exact hdis hga

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
    · split at h
      · exact hsFail_legal _ _ _ _ _ h hnt
      · cases hsel : selectGroup vch.offeredShares
            ((Option.map (fun x => x.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD []) with
        | none =>
          simp only [hsel] at h
          have hl := hsFail_legal _ _ _ _ _ h hnt
          exact hl
        | some gp =>
          obtain ⟨selGroup, selShare⟩ := gp
          simp only [hsel, State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
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
  split at h
  · split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
        or_self, or_false] at hmem
    · split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
          or_self, or_false] at hmem
      · cases hsel : selectGroup vch.offeredShares
            ((Option.map (fun x => x.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD []) with
        | none =>
          simp only [hsel, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
            or_self, or_false] at hmem
        | some gp =>
          obtain ⟨selGroup, selShare⟩ := gp
          simp only [hsel, State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
            or_self, or_false] at hmem
  · simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_self, or_false] at hmem

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
  split at h
  · split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
        or_self, or_false] at hmem
    · split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
          or_self, or_false] at hmem
      · cases hsel : selectGroup vch.offeredShares
            ((Option.map (fun x => x.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD []) with
        | none =>
          simp only [hsel, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
            or_self, or_false] at hmem
        | some gp =>
          obtain ⟨selGroup, selShare⟩ := gp
          simp only [hsel, State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
            or_self, or_false] at hmem
  · simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_self, or_false] at hmem

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
  split at h
  · split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
        or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem
    · split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
          or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem
      · cases hsel : selectGroup vch.offeredShares
            ((Option.map (fun x => x.namedGroups) (selectEndpoint s.serverConfig vch.sni)).getD []) with
        | none =>
          simp only [hsel, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
            or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem
        | some gp =>
          obtain ⟨selGroup, selShare⟩ := gp
          simp only [hsel, State.allocOp, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
            or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem
  · simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
      or_self, or_false, and_false, OutputAction.callCrypto.injEq] at hmem

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
