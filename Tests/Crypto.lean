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
  let (_, s) := s.allocOp .aeadOpen .application (some .read)
  { s with handshake := .connected }

def stateAfter (s : State) (ev : InputEvent) : Option State :=
  match step s ev with
  | .ok (s', _) => some s'
  | .error _ => none

def checks : List Check :=
  [ -- capability validation
    { name := "fake provider supports the required initial crypto set"
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
    , ok := (match fakeProvider.submit ⟨0⟩ (.ecdheX25519 (ByteArray.mk #[])) with
             | .ok (.sharedSecret _) => true | _ => false) }
  , { name := "fake provider: Finished verification succeeds"
    , ok := (match fakeProvider.submit ⟨0⟩ (.verifyFinished .sha256 (ByteArray.mk #[]) (ByteArray.mk #[])) with
             | .ok .verified => true | _ => false) }
  , { name := "fake provider: AEAD seal echoes the plaintext envelope deterministically"
    , ok := (match fakeProvider.submit ⟨0⟩
               (.aeadSeal { conn := ⟨0,0⟩, direction := .write, epoch := .application,
                            seq := SeqNo.zero, suite := .aes128GcmSha256,
                            contentRole := .applicationData } (ByteArray.mk #[]) (ByteArray.mk #[7,7,7])) with
             | .ok (.aeadSealed ct) => ct.toList == [7,7,7] | _ => false) }
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
