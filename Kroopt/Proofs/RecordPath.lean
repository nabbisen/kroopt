import Kroopt.Core.Step
import Kroopt.Proofs.Handshake

/-!
# Kroopt.Proofs.RecordPath

Safety proofs for the record-layer transitions (RFC 004 §10, RFC 015 §15.1).

1. **Handler no-emit lemmas.** None of the record handlers
   (`handleTransportBytes`, `handleCryptoResult`, `handleAppSend`) ever produces
   an `emitPlaintext` action. These feed the top-level *no early plaintext*
   theorem in `ActionDiscipline`, keeping application plaintext emitted from a
   single `connected`-gated site.
2. **No unauthenticated plaintext / auth-failure.** An AEAD-open failure is
   fatal with no plaintext, and buffered plaintext arises only from a successful
   authenticated open (see `ActionDiscipline.buffered_plaintext_provenance`).

All proofs are `sorry`/`axiom`/`unsafe`-free.
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- The plaintext-handshake-record dispatch emits no application plaintext: it
routes to handshake transitions (each proved no-emit) or a clean decode failure. -/
theorem handshakeOnPlaintextRecord_no_emit
    (s s' : State) (body : ByteArray) (acts : List OutputAction)
    (h : handshakeOnPlaintextRecord s body = .ok (s', acts))
    (c : ConnId) (bb : ByteArray) : OutputAction.emitPlaintext c bb ∉ acts := by
  intro hmem
  unfold handshakeOnPlaintextRecord recordFailAlert at h
  split at h
  · split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
        or_self, or_false, false_or] at hmem
    · exact handshakeOnClientHello_no_emit _ _ _ _ _ h c bb hmem
  · split at h
    · exact onClientFinishedBytes_no_emit _ _ _ _ h c bb hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.not_mem_nil] at hmem

/-- The plaintext-handshake-record dispatch accepts no application plaintext. -/
theorem handshakeOnPlaintextRecord_no_accept
    (s s' : State) (body : ByteArray) (acts : List OutputAction)
    (h : handshakeOnPlaintextRecord s body = .ok (s', acts))
    (c : ConnId) (n : Nat) : OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro hmem
  unfold handshakeOnPlaintextRecord recordFailAlert at h
  split at h
  · split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
        or_self, or_false, false_or] at hmem
    · exact handshakeOnClientHello_no_accept _ _ _ _ _ h c n hmem
  · split at h
    · exact onClientFinishedBytes_no_accept _ _ _ _ h c n hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.not_mem_nil] at hmem

/-- The plaintext-handshake-record dispatch requests no AEAD-open: it routes to
ECDHE / Finished-verify requests, never an application record open. -/
theorem handshakeOnPlaintextRecord_no_aeadOpen
    (s s' : State) (body : ByteArray) (acts : List OutputAction)
    (h : handshakeOnPlaintextRecord s body = .ok (s', acts))
    (c : ConnId) (oid : OperationId) (meta : RecordCryptoMeta) (aad ct : ByteArray) :
    OutputAction.callCrypto c oid (CryptoOp.aeadOpen meta aad ct) ∉ acts := by
  intro hmem
  unfold handshakeOnPlaintextRecord recordFailAlert at h
  split at h
  · split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
        or_self, or_false, false_or] at hmem
    · exact handshakeOnClientHello_no_aeadOpen _ _ _ _ _ h c oid meta aad ct hmem
  · split at h
    · exact onClientFinishedBytes_no_aeadOpen _ _ _ _ h c oid meta aad ct hmem
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      simp only [List.not_mem_nil] at hmem

/-- Shared closer: after splitting a handler into its leaves, each leaf returns a
concrete action list with no `emitPlaintext`, contradicting membership. -/
private theorem handleTransportBytes_no_emit
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleTransportBytes s b = .ok (s', acts)) :
    ∀ (c : ConnId) (bb : ByteArray), OutputAction.emitPlaintext c bb ∉ acts := by
  intro c bb hmem
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
    | exact handshakeOnPlaintextRecord_no_emit _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_emit _ _ _ _ _ h _ _ hmem
    | exact handshakeOnPlaintextRecord_no_accept _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_accept _ _ _ _ _ h _ _ hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false, false_or] at hmem))

/-- `handleCryptoResult` never emits application plaintext — decrypted content is
buffered, not emitted (RFC 004 §5.7). -/
private theorem handleCryptoResult_no_emit
    (s s' : State) (op : OperationId) (r : CryptoResult) (acts : List OutputAction)
    (h : handleCryptoResult s op r = .ok (s', acts)) :
    ∀ (c : ConnId) (bb : ByteArray), OutputAction.emitPlaintext c bb ∉ acts := by
  intro c bb hmem
  unfold handleCryptoResult handleCryptoResultCorrelated recordFailAlert at h
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
    | exact handshakeOnPlaintextRecord_no_emit _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_emit _ _ _ _ _ h _ _ hmem
    | exact handshakeOnPlaintextRecord_no_accept _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_accept _ _ _ _ _ h _ _ hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false, false_or] at hmem))

/-- `handleAppSend` never emits application plaintext (it requests a seal and
acknowledges ownership). -/
private theorem handleAppSend_no_emit
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleAppSend s b = .ok (s', acts)) :
    ∀ (c : ConnId) (bb : ByteArray), OutputAction.emitPlaintext c bb ∉ acts := by
  intro c bb hmem
  unfold handleAppSend recordFailAlert at h
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
    | exact handshakeOnPlaintextRecord_no_emit _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_emit _ _ _ _ _ h _ _ hmem
    | exact handshakeOnPlaintextRecord_no_accept _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_accept _ _ _ _ _ h _ _ hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false, false_or] at hmem))

private theorem handleTransportBytes_no_accept'
    (s s' : State) (b : ByteArray) (acts : List OutputAction)
    (h : handleTransportBytes s b = .ok (s', acts)) :
    ∀ (c : ConnId) (n : Nat), OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro c n hmem
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
    | exact handshakeOnPlaintextRecord_no_emit _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_emit _ _ _ _ _ h _ _ hmem
    | exact handshakeOnPlaintextRecord_no_accept _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_accept _ _ _ _ _ h _ _ hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false, false_or] at hmem))

private theorem handleCryptoResult_no_accept'
    (s s' : State) (op : OperationId) (r : CryptoResult) (acts : List OutputAction)
    (h : handleCryptoResult s op r = .ok (s', acts)) :
    ∀ (c : ConnId) (n : Nat), OutputAction.acceptPlaintextBytes c n ∉ acts := by
  intro c n hmem
  unfold handleCryptoResult handleCryptoResultCorrelated recordFailAlert at h
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
    | exact handshakeOnPlaintextRecord_no_emit _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_emit _ _ _ _ _ h _ _ hmem
    | exact handshakeOnPlaintextRecord_no_accept _ _ _ _ h _ _ hmem
    | exact handshakeOnGatingResult_no_accept _ _ _ _ _ h _ _ hmem
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨-, rfl⟩ := h
       simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, reduceCtorEq,
         or_self, or_false, false_or] at hmem))

/-- The three handlers, packaged for `ActionDiscipline`: none emits plaintext. -/
theorem handleTransportBytes_no_plaintext
    {s s' : State} {b : ByteArray} {acts : List OutputAction}
    (h : handleTransportBytes s b = .ok (s', acts))
    {c : ConnId} {bb : ByteArray} : OutputAction.emitPlaintext c bb ∉ acts :=
  handleTransportBytes_no_emit s s' b acts h c bb

theorem handleCryptoResult_no_plaintext
    {s s' : State} {op : OperationId} {r : CryptoResult} {acts : List OutputAction}
    (h : handleCryptoResult s op r = .ok (s', acts))
    {c : ConnId} {bb : ByteArray} : OutputAction.emitPlaintext c bb ∉ acts :=
  handleCryptoResult_no_emit s s' op r acts h c bb

theorem handleAppSend_no_plaintext
    {s s' : State} {b : ByteArray} {acts : List OutputAction}
    (h : handleAppSend s b = .ok (s', acts))
    {c : ConnId} {bb : ByteArray} : OutputAction.emitPlaintext c bb ∉ acts :=
  handleAppSend_no_emit s s' b acts h c bb

theorem handleTransportBytes_no_accept
    {s s' : State} {b : ByteArray} {acts : List OutputAction}
    (h : handleTransportBytes s b = .ok (s', acts))
    {c : ConnId} {n : Nat} : OutputAction.acceptPlaintextBytes c n ∉ acts :=
  handleTransportBytes_no_accept' s s' b acts h c n

theorem handleCryptoResult_no_accept
    {s s' : State} {op : OperationId} {r : CryptoResult} {acts : List OutputAction}
    (h : handleCryptoResult s op r = .ok (s', acts))
    {c : ConnId} {n : Nat} : OutputAction.acceptPlaintextBytes c n ∉ acts :=
  handleCryptoResult_no_accept' s s' op r acts h c n

/-- **AEAD-open failure emits no plaintext and is terminal.** A verification
failure on an *outstanding* record-open operation maps to a fatal
`bad_record_mac`, clears the plaintext buffer, and emits no `emitPlaintext`
(RFC 004 §12). (For a *stale* operation id the result is dropped instead —
`stale_crypto_result_rejected`.) -/
theorem aead_open_failure_no_plaintext
    (s s' : State) (c : ConnId) (op : OperationId) (acts : List OutputAction)
    (h : step s (.cryptoResult c op .verifyFailed) = .ok (s', acts))
    (hnt : s.handshake.isTerminal = false)
    (hpend : s.pendingOps.contains op = true) :
    (∀ (cc : ConnId) (bb : ByteArray), OutputAction.emitPlaintext cc bb ∉ acts)
    ∧ s'.pendingPlainOut = none
    ∧ s'.handshake.isTerminal = true := by
  unfold step at h
  rw [hnt] at h
  simp only [Bool.false_eq_true, if_false, reduceIte] at h
  unfold handleCryptoResult at h
  rw [if_pos hpend] at h
  unfold handleCryptoResultCorrelated recordFailAlert at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨hs, ha⟩ := h
  refine ⟨?_, ?_, ?_⟩
  · intro cc bb hmem
    rw [← ha] at hmem
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil,
      reduceCtorEq, or_self, or_false] at hmem
  · rw [← hs]
  · rw [← hs]; rfl

/-- **Operation-id correlation (RFC 008 §5, RFC 015 §9.13).** A crypto result
whose operation id is **not** outstanding — stale, duplicate, or forged — is a
complete no-op: the state is unchanged and no actions are emitted. This is the
gate that stops a late or replayed provider answer from perturbing the protocol;
in particular no plaintext can be buffered or emitted through a stale result. -/
theorem stale_crypto_result_rejected
    (s s' : State) (op : OperationId) (r : CryptoResult) (acts : List OutputAction)
    (hstale : s.pendingOps.contains op = false)
    (h : handleCryptoResult s op r = .ok (s', acts)) :
    s' = s ∧ acts = [] := by
  unfold handleCryptoResult at h
  rw [if_neg (by rw [hstale]; decide)] at h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  exact ⟨h.1.symm, h.2.symm⟩

/-- A stale crypto result emits no application plaintext (corollary of
`stale_crypto_result_rejected`). -/
theorem stale_crypto_result_no_plaintext
    (s s' : State) (op : OperationId) (r : CryptoResult) (acts : List OutputAction)
    (hstale : s.pendingOps.contains op = false)
    (h : handleCryptoResult s op r = .ok (s', acts))
    (c : ConnId) (bb : ByteArray) : OutputAction.emitPlaintext c bb ∉ acts := by
  have := (stale_crypto_result_rejected s s' op r acts hstale h).2
  rw [this]; simp only [List.not_mem_nil, not_false_iff]

/-- **No unauthenticated plaintext (headline, RFC 004 §10, RFC 015 §15.1).**
If handling an `aeadOpened` crypto result newly buffers application plaintext
(`pendingPlainOut` becomes `some b`, having not already been `some b`), then the
connection was `connected`. Because the AEAD provider only returns `aeadOpened`
for a record whose tag *verified*, buffered application plaintext always
originates from an authenticated decryption — never from raw transport bytes.

Combined with `no_plaintext_emit_unless_connected` and the fact that the sole
`emitPlaintext` site reads `pendingPlainOut`, this is the end-to-end guarantee a
dependent relies on: no plaintext reaches the application unless it came from an
authenticated, connected-state record open. -/
theorem buffered_plaintext_authenticated
    (s s' : State) (op : OperationId) (pt : ByteArray) (acts : List OutputAction)
    (h : handleCryptoResult s op (.aeadOpened pt) = .ok (s', acts))
    (b : ByteArray) (hb : s'.pendingPlainOut = some b)
    (hne : s.pendingPlainOut ≠ some b) :
    s.handshake.isConnected = true := by
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
  all_goals (
    first
    | assumption
    | (simp only [Except.ok.injEq, Prod.mk.injEq] at h
       obtain ⟨hs, -⟩ := h
       rw [← hs] at hb
       first
       | assumption
       | exact absurd hb hne
       | simp only [reduceCtorEq] at hb))

/-- **Step-level provenance of newly-buffered plaintext.** If processing an
`aeadOpened` crypto result newly buffers application plaintext, the connection
was `connected` (the step either absorbs in a terminal state — impossible here
since that would leave the buffer unchanged — or dispatches to
`buffered_plaintext_authenticated`). -/
theorem buffered_plaintext_provenance
    (s s' : State) (c : ConnId) (op : OperationId) (pt : ByteArray)
    (acts : List OutputAction)
    (h : step s (.cryptoResult c op (.aeadOpened pt)) = .ok (s', acts))
    (b : ByteArray) (hb : s'.pendingPlainOut = some b)
    (hne : s.pendingPlainOut ≠ some b) :
    s.handshake.isConnected = true := by
  unfold step at h
  split at h
  · -- terminal: state unchanged, so hb contradicts hne
    simp only [absorbTerminal, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, -⟩ := h; rw [← hs] at hb; exact absurd hb hne
  · -- non-terminal: dispatches to the record open handler
    exact buffered_plaintext_authenticated s s' op pt acts h b hb hne

end Proofs
end Kroopt.Core
