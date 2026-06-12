import Kroopt.Core.Step
import Kroopt.Core.Nonce

/-!
# Tests.Nonce

Unit and negative tests for the sequence/nonce/key-separation layer (RFC 005
§10). Pure: no sockets, no real crypto. These pin the concrete behaviour the
proofs guarantee — sequence increment and overflow, distinct nonces for distinct
sequences, the direction/epoch metadata on every record crypto op, and rejection
of stale crypto results (wrong op id).
-/

namespace Tests.Nonce

open Kroopt Kroopt.Core

structure Check where
  name : String
  ok : Bool

def bytes (l : List UInt8) : ByteArray := ByteArray.mk l.toArray

def connectedState : State :=
  let s := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
  { s with handshake := .connected
           readEpoch := { s.readEpoch with epoch := .application }
           writeEpoch := { s.writeEpoch with epoch := .application } }

/-- A connected state whose write sequence is one below the `UInt64` ceiling, so
the next seal would overflow. -/
def writeAtMax : State :=
  let s := connectedState
  { s with writeEpoch := { s.writeEpoch with seq := ⟨0xFFFFFFFFFFFFFFFF⟩ } }

/-- Inspect the metadata of the first record crypto op a step emits. -/
def firstCryptoMeta (s : State) (ev : InputEvent) : Option RecordCryptoMeta :=
  match step s ev with
  | .ok (_, acts) =>
      acts.findSome? (fun a =>
        match a with
        | .callCrypto _ _ (.aeadSeal meta _ _) => some meta
        | .callCrypto _ _ (.aeadOpen meta _ _) => some meta
        | _ => none)
  | .error _ => none

def appRecord (body : List UInt8) : ByteArray :=
  let len := body.length
  bytes ([23, 0x03, 0x03, (UInt8.ofNat (len / 256)), (UInt8.ofNat (len % 256))] ++ body)

def checks : List Check :=
  -- Sequence increment / overflow
  [ { name := "SeqNo.next increments the value by one"
    , ok := (match (SeqNo.zero).next with | some s => s.value == 1 | none => false) }
  , { name := "SeqNo.next returns none exactly at the ceiling"
    , ok := (SeqNo.mk 0xFFFFFFFFFFFFFFFF).next.isNone
            && (SeqNo.mk 0xFFFFFFFFFFFFFFFE).next.isSome }
  , { name := "connected send advances the write sequence by one"
    , ok := (match step connectedState (.appSend ⟨0,0⟩ (bytes [1,2,3])) with
             | .ok (s', _) => s'.writeEpoch.seq.value == 1
             | .error _    => false) }
  , { name := "send at the sequence ceiling fails (no silent wrap)"
    , ok := (match step writeAtMax (.appSend ⟨0,0⟩ (bytes [1,2,3])) with
             | .ok (s', acts) =>
                 s'.handshake.isTerminal
                 && !acts.any (fun a => match a with | .callCrypto _ _ _ => true | _ => false)
             | .error _ => false) }
  -- Nonce uniqueness
  , { name := "distinct sequences derive distinct (modeled) nonces"
    , ok := deriveNonce 7 (SeqNo.mk 1) != deriveNonce 7 (SeqNo.mk 2) }
  , { name := "same sequence + IV base derives the same nonce"
    , ok := deriveNonce 7 (SeqNo.mk 5) == deriveNonce 7 (SeqNo.mk 5) }
  , { name := "concrete nonce bytes differ for distinct sequences"
    , ok := (nonceBytes (bytes (List.replicate 12 0xAA)) 12 (SeqNo.mk 1)).toList
            != (nonceBytes (bytes (List.replicate 12 0xAA)) 12 (SeqNo.mk 2)).toList }
  , { name := "concrete nonce is the IV when sequence is zero"
    , ok := (nonceBytes (bytes (List.replicate 12 0xAA)) 12 (SeqNo.mk 0)).toList
            == (bytes (List.replicate 12 0xAA)).toList }
  -- Directional + epoch metadata on emitted crypto ops
  , { name := "seal op carries write-direction, application-epoch metadata"
    , ok := (match firstCryptoMeta connectedState (.appSend ⟨0,0⟩ (bytes [1,2,3])) with
             | some meta => meta.direction == .write && meta.epoch == .application
             | none      => false) }
  , { name := "open op carries read-direction, application-epoch metadata"
    , ok := (match firstCryptoMeta connectedState (.transportBytes ⟨0,0⟩ (appRecord [9,9,9])) with
             | some meta => meta.direction == .read && meta.epoch == .application
             | none      => false) }
  -- Stale crypto result: an unknown op id must not buffer plaintext
  , { name := "stale aeadOpened (no matching pending op) buffers no plaintext (RFC 008 §5)"
    , ok := (match step connectedState
               (.cryptoResult ⟨0,0⟩ ⟨999⟩ (.aeadOpened (bytes [0x41, 23]))) with
             | .ok (s', _) => s'.pendingPlainOut.isNone   -- correlation guard drops stale result
             | .error _    => false) }
  , { name := "aeadOpened before connected buffers no plaintext"
    , ok := (match step (State.initial ⟨0,0⟩ ⟨0⟩ .sha256)
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (bytes [0x41, 23]))) with
             | .ok (s', _) => s'.pendingPlainOut.isNone
             | .error _    => true) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M3 sequence/nonce/key-separation tests:"
  for c in checks do
    if c.ok then
      IO.println s!"  PASS  {c.name}"
    else
      IO.println s!"  FAIL  {c.name}"
      failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Nonce

def main : IO UInt32 := Tests.Nonce.main
