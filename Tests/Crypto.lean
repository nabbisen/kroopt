import Kroopt.Crypto.Provider
import Kroopt.Core.Step

/-!
# Tests.Crypto

Capability-negotiation tests (RFC 008 §3, §10), deterministic fake-provider
tests, and a runtime cross-check of the operation-id correlation guard
(RFC 008 §5) that is proved in `Kroopt.Core.Proofs.stale_crypto_result_rejected`.
-/

namespace Tests.Crypto

open Kroopt Kroopt.Core Kroopt.Crypto

structure Check where
  name : String
  ok : Bool

def requiredInitial : RequiredCrypto :=
  { suites := [.aes128GcmSha256, .chacha20Poly1305Sha256]
    groups := [.x25519]
    signatureSchemes := [.ed25519, .ecdsaSecp256r1Sha256]
    hashAlgorithms := [.sha256] }

/-- A capability set missing X25519 and Ed25519 (a deliberately weak provider). -/
def weakCaps : CryptoCapabilities :=
  { suites := [.aes128GcmSha256, .chacha20Poly1305Sha256]
    hashAlgorithms := [.sha256]
    groups := [.secp256r1]
    signatureSchemes := [.ecdsaSecp256r1Sha256]
    randomSource := .osCsprng
    supportsSecretHandles := true }

def noEntropyCaps : CryptoCapabilities :=
  { fakeCapabilities with randomSource := .none }

/-- A connected state with operation id 0 outstanding (a record-open). -/
def connectedWithOp : State :=
  let s := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
  let (_, s) := (s.allocOp .aeadOpen .application (some .read) ResourceLimits.standard.maxPendingCryptoOps).toOption.getD (⟨0⟩, s)
  { s with handshake := .connected }

/-- RFC 037 §4.1 — a state carrying exactly `n` outstanding pending crypto ops, used to
probe the `maxPendingCryptoOps` budget boundary directly. -/
def opsAtDepth (n : Nat) : State :=
  let s := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
  { s with pendingOps := ⟨(List.range n).map
      (fun _ => { id := ⟨0⟩, expectedKind := .aeadSeal,
                  expectedEpoch := .application, expectedDirection := some .write })⟩ }

/-- `true` iff `allocOp` at op-depth `n` under cap `cap` reports the budget error. -/
def allocErrorsAtCap (n cap : Nat) : Bool :=
  match (opsAtDepth n).allocOp .aeadSeal .application (some .write) cap with
  | .error .pendingCryptoOps => true
  | _ => false

/-- `true` iff `allocOp` at op-depth `n` under cap `cap` succeeds (registers the op). -/
def allocSucceedsAtCap (n cap : Nat) : Bool :=
  match (opsAtDepth n).allocOp .aeadSeal .application (some .write) cap with
  | .ok _ => true
  | _ => false

/-- A *connected* state already at the pending-op budget; the next seal cannot register. -/
def connectedAtBudget : State :=
  { (opsAtDepth ResourceLimits.standard.maxPendingCryptoOps) with handshake := .connected }

/-- Drive an application send from the budget-saturated connected state. -/
def appSendAtBudget : Option (State × List OutputAction) :=
  match step connectedAtBudget (.appSend ⟨0, 0⟩ (ByteArray.mk #[0x41])) with
  | .ok r => some r
  | .error _ => none

def stateAfter (s : State) (ev : InputEvent) : Option State :=
  match step s ev with
  | .ok (s', _) => some s'
  | .error _ => none

-- RFC 041 review: record-path fatal alerts must transmit a `writeAlert` (with the peer-fatal exclusion).
def s0Init : State := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
def sHsWrite : State := { s0Init with writeEpoch := installEpoch .handshake }
def connectedAppWrite : State := { connectedWithOp with writeEpoch := installEpoch .application }

/-- The epoch of the first `writeAlert` in an action list, if any. -/
def writeAlertEpoch? (acts : List OutputAction) : Option Epoch :=
  acts.foldl (fun acc a => match acc, a with
    | none, .writeAlert _ ep _ _ => some ep | _, _ => acc) none
def hasOrdinaryWrite (acts : List OutputAction) : Bool :=
  acts.any (fun a => match a with | .writeTransport .. => true | _ => false)
def hasEmit (acts : List OutputAction) : Bool :=
  acts.any (fun a => match a with | .emitPlaintext .. => true | _ => false)
def hasAccept (acts : List OutputAction) : Bool :=
  acts.any (fun a => match a with | .acceptPlaintextBytes .. => true | _ => false)

def checks : List Check :=
  [ -- RFC 037 §4.1 crypto-op budget enforcement
    { name := "allocOp at the pending-op budget fails closed (.pendingCryptoOps)"
    , ok := allocErrorsAtCap ResourceLimits.standard.maxPendingCryptoOps
              ResourceLimits.standard.maxPendingCryptoOps }
  , { name := "allocOp one below the budget still registers the op"
    , ok := allocSucceedsAtCap (ResourceLimits.standard.maxPendingCryptoOps - 1)
              ResourceLimits.standard.maxPendingCryptoOps }
  , { name := "allocOp above the budget fails closed"
    , ok := allocErrorsAtCap (ResourceLimits.standard.maxPendingCryptoOps + 3)
              ResourceLimits.standard.maxPendingCryptoOps }
  , { name := "app-send at the budget fails closed: terminal, internalError alert, no seal"
    , ok := (match appSendAtBudget with
             | some (s', acts) =>
                 s'.handshake.isTerminal
                 && acts.any (fun a => match a with | .failWithAlert _ .internalError => true | _ => false)
                 && acts.all (fun a => match a with | .callCrypto _ _ _ => false | _ => true)
             | none => false) }
    -- RFC 037 §4.1 clear-on-failure: a correlated crypto *failure* retires its op (so the
    -- pending set stays exactly-once-consistent) and fails the connection closed.
  , { name := "a verify-failed crypto result clears its op and fails closed"
    , ok := (match handleCryptoResult connectedWithOp ⟨0⟩ .verifyFailed with
             | .ok (s', _) => s'.handshake.isTerminal && (s'.pendingOps.contains ⟨0⟩ == false)
             | .error _ => false) }
  , { name := "a provider-failed crypto result clears its op and fails closed"
    , ok := (match handleCryptoResult connectedWithOp ⟨0⟩ (.failed .providerInternal) with
             | .ok (s', _) => s'.handshake.isTerminal && (s'.pendingOps.contains ⟨0⟩ == false)
             | .error _ => false) }
    -- capability validation
  , { name := "fake provider supports the required initial crypto set"
    , ok := (match validateCapabilities fakeCapabilities requiredInitial with
             | .ok () => true | _ => false) }
  , { name := "weak provider missing X25519 is rejected (config error)"
    , ok := (match validateCapabilities weakCaps requiredInitial with
             | .error (.unsupportedGroup .x25519) => true
             | _ => false) }
  , { name := "weak provider missing Ed25519 is rejected when group is supplied"
    , ok := (match validateCapabilities weakCaps
               { requiredInitial with groups := [.secp256r1] } with
             | .error (.unsupportedSignatureScheme .ed25519) => true
             | _ => false) }
  , { name := "a provider with no entropy source is fatal"
    , ok := (match validateCapabilities noEntropyCaps requiredInitial with
             | .error .noRandomSource => true | _ => false) }
    -- deterministic fake provider
  , { name := "fake provider: ECDHE returns a shared-secret handle"
    , ok := (match fakeProvider.submit Kroopt.Crypto.SecretArena.empty ⟨0⟩ (.ecdheX25519 (ByteArray.mk #[])) with
             | .ok (_, .ecdheComplete _ _) => true | _ => false) }
  , { name := "fake provider: Finished verification succeeds"
    , ok := (match fakeProvider.submit Kroopt.Crypto.SecretArena.empty ⟨0⟩ (.verifyFinished .sha256 (ByteArray.mk #[]) (ByteArray.mk #[])) with
             | .ok (_, .verified) => true | _ => false) }
  , { name := "fake provider: AEAD seal echoes the plaintext envelope deterministically"
    , ok := (match fakeProvider.submit Kroopt.Crypto.SecretArena.empty ⟨0⟩
               (.aeadSeal { conn := ⟨0,0⟩, direction := .write, epoch := .application,
                            seq := SeqNo.zero, suite := .aes128GcmSha256,
                            contentRole := .applicationData } (ByteArray.mk #[]) (ByteArray.mk #[7,7,7])) with
             | .ok (_, .aeadSealed ct) => ct.toList == [7,7,7] | _ => false) }
    -- operation-id correlation guard (RFC 008 §5)
  , { name := "outstanding op: a returning result is processed (buffers plaintext)"
    , ok := (match stateAfter connectedWithOp
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (ByteArray.mk #[0x41, 0x42, 23]))) with
             | some s' => s'.pendingPlainOut.isSome | none => false) }
  , { name := "stale op id (id 99, not outstanding) is dropped with no state change"
    , ok := (match stateAfter connectedWithOp
               (.cryptoResult ⟨0,0⟩ ⟨99⟩ (.aeadOpened (ByteArray.mk #[0x41, 0x42, 23]))) with
             | some s' => s'.pendingPlainOut.isNone && s'.handshake == .connected
             | none => false) }
  , { name := "stale op id buffers no plaintext even with a valid-looking record"
    , ok := (match stateAfter connectedWithOp
               (.cryptoResult ⟨0,0⟩ ⟨7⟩ (.aeadOpened (ByteArray.mk #[0x99, 23]))) with
             | some s' => s'.pendingPlainOut.isNone | none => false) }
  , { name := "duplicate result: second delivery of a consumed op id is a no-op"
    , ok := (match stateAfter connectedWithOp
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (ByteArray.mk #[0x41, 23]))) with
             | some s1 =>
                 -- op 0 is now cleared; replaying it must not buffer again
                 (match stateAfter { s1 with pendingPlainOut := none }
                    (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (ByteArray.mk #[0x43, 23]))) with
                  | some s2 => s2.pendingPlainOut.isNone | none => false)
             | none => false) }
  , -- RFC 041 review: record-path fatal alerts are transmitted (writeAlert), with the peer-fatal exclusion
    { name := "record-path: initial-epoch fatal emits a plaintext writeAlert(initial)"
    , ok := (match recordFailAlert s0Init .decodeError (.parse .truncated) with
             | .ok (_, acts) => writeAlertEpoch? acts == some .initial
             | .error _ => false) }
  , { name := "record-path: post-connected verifyFailed clears its op and emits writeAlert(application)"
    , ok := (match handleCryptoResult connectedAppWrite ⟨0⟩ .verifyFailed with
             | .ok (s', acts) => s'.handshake.isTerminal && (s'.pendingOps.contains ⟨0⟩ == false)
                                 && writeAlertEpoch? acts == some .application
             | .error _ => false) }
  , { name := "record-path: handshake-epoch fatal emits writeAlert(handshake) (protected where keys exist)"
    , ok := (match recordFailAlert sHsWrite .badRecordMac (.protocol .badFinished) with
             | .ok (_, acts) => writeAlertEpoch? acts == some .handshake
             | .error _ => false) }
  , { name := "record-path: provider-failed crypto result clears its op and emits a writeAlert"
    , ok := (match handleCryptoResult connectedAppWrite ⟨0⟩ (.failed .providerInternal) with
             | .ok (s', acts) => (s'.pendingOps.contains ⟨0⟩ == false) && (writeAlertEpoch? acts).isSome
             | .error _ => false) }
  , { name := "record-path: a peer fatal alert draws NO response writeAlert (abortive close)"
    , ok := (match onInboundAlert s0Init (ByteArray.mk #[1, 40]) with
             | .ok (_, acts) => (writeAlertEpoch? acts).isNone
                                && acts.any (fun a => match a with
                                     | .closeTransport _ .abortive => true | _ => false)
             | .error _ => false) }
  , { name := "record-path: recordFailAlert emits no plaintext, no app-accept, no ordinary writeTransport"
    , ok := (match recordFailAlert s0Init .internalError (.protocol .badFinished) with
             | .ok (_, acts) => !hasEmit acts && !hasAccept acts && !hasOrdinaryWrite acts
             | .error _ => false) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M6 crypto provider + correlation tests:"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Crypto

def main : IO UInt32 := Tests.Crypto.main
