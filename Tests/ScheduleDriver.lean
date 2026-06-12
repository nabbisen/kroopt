import Kroopt.Core.KeyScheduleDriver
import Kroopt.Crypto.RealProvider
import Kroopt.Crypto.Arena
import Kroopt.Crypto.Hacl
import Kroopt.Core.Crypto
import Kroopt.Core.Record
import Kroopt.Core.Id

/-!
# Tests.ScheduleDriver

End-to-end check that the **verified core orchestrator**
(`Kroopt.Core.KeyScheduleDriver`) drives the **real provider**
(`Kroopt.Crypto.mkRealProvider`) through the entire TLS 1.3 key schedule. Unlike
the M14 `realprovider` test — which scripted the operation sequence by hand — here
the op sequence comes from the orchestrator: it emits each op, the real provider
answers it on real HACL\* crypto threading the arena, and the result is fed back to
the orchestrator to get the next op, until it reaches `complete`. Then every
secret the orchestrator collected (read back from the arena by handle) and the
installed handshake key/IV are compared to the RFC 8448 §3 trace.
-/

namespace Tests.ScheduleDriver

open Kroopt.Crypto
open Kroopt.Core (CryptoResult Direction Epoch CipherSuite)
open Kroopt.Core.KeyScheduleDriver

def hexToBytes (s : String) : ByteArray := Id.run do
  let cs := s.toList.toArray
  let hv : Char → UInt8 := fun c =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8 else 0
  let mut out := ByteArray.empty
  let mut i := 0
  while i + 1 < cs.size do
    out := out.push (hv cs[i]! * 16 + hv cs[i+1]!); i := i + 2
  return out

def eqB (a b : ByteArray) : Bool := a.toList == b.toList

-- RFC 8448 §3 vectors
def clientPub  := "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
def serverPriv := "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
def ecdhe      := "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
def handshake  := "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
def th1        := "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
def sHs        := "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
def master     := "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
def th2        := "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
def sAp        := "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
def sHsKey     := "3fce516009c21727d0f2e4e86ee403bc"
def sHsIv      := "5d313eb2671276ee13000b30"
def emptyHashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/-- Fuel-bounded loop: feed the awaited result to the orchestrator, submit the op
it emits to the real provider, repeat until the orchestrator reaches `complete`. -/
def drive (cfg : RealCryptoConfig) : Nat → State → SecretArena → CryptoResult →
    Except Kroopt.CryptoError (State × SecretArena)
  | 0, _, _, _ => .error .providerInternal
  | fuel + 1, st, a, r =>
    if st.phase = .complete ∨ st.phase = .handshakeKeysInstalled then .ok (st, a)
    else
      match advance st r with
      | .error _ => .error .providerInternal
      | .ok (st', ops) =>
        match ops with
        | [] => drive cfg fuel st' a r
        | op :: _ =>
          match RealProvider.submit cfg a ⟨0⟩ op with
          | .error e => .error e
          | .ok (a', r') => drive cfg fuel st' a' r'

def runChecks : Except Kroopt.CryptoError (List (String × Bool)) := do
  let certPriv := hexToBytes "9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f"
  let cfg : RealCryptoConfig :=
    { ephemeralPrivate := hexToBytes serverPriv, certPrivate := certPriv
    , certPublic := Kroopt.Crypto.Hacl.ed25519Public certPriv }
  -- the verified orchestrator produces the opening ECDHE op (handshake-key stage,
  -- knowing only the CH..ServerHello transcript)
  let (st0, op0) := start .aes128GcmSha256 (hexToBytes clientPub)
                      (hexToBytes emptyHashHex) (hexToBytes th1)
  let (a0, r0) ← RealProvider.submit cfg SecretArena.empty ⟨0⟩ op0
  -- stage 1: drive to the handshake-keys pause
  let (st1, a1) ← drive cfg 64 st0 a0 r0
  -- stage 2: the server flight is now committed, so the CH..server-Finished
  -- transcript is known; resume the application-key stage with it
  let (st2, ops2) ← (resumeApplication st1 (hexToBytes th2)).mapError (fun _ => Kroopt.CryptoError.providerInternal)
  let (a2, st, a) ← (match ops2 with
    | op :: _ => do
        let (a2, r2) ← RealProvider.submit cfg a1 ⟨0⟩ op
        let (st, a) ← drive cfg 64 st2 a2 r2
        pure (a2, st, a)
    | [] => .error .providerInternal)
  let _ := a2

  let getEq : Option Kroopt.Core.SecretKeyHandle → String → Bool :=
    fun oh hex => match oh with
      | some h => (match a.get h with | some b => eqB b (hexToBytes hex) | none => false)
      | none => false
  let installedKeyEq (dir : Direction) (epoch : Epoch) (hex : String) : Bool :=
    match a.lookupInstalled dir epoch with
    | some (k, _) => (match a.getById k with | some b => eqB b (hexToBytes hex) | none => false)
    | none => false
  let installedIvEq (dir : Direction) (epoch : Epoch) (hex : String) : Bool :=
    match a.lookupInstalled dir epoch with
    | some (_, iv) => (match a.getById iv with | some b => eqB b (hexToBytes hex) | none => false)
    | none => false
  let installedPresent (dir : Direction) (epoch : Epoch) : Bool :=
    (a.lookupInstalled dir epoch).isSome

  let checks : List (String × Bool) :=
    [ ("handshake-key stage paused at handshakeKeysInstalled", decide (st1.phase = .handshakeKeysInstalled))
    , ("application-key stage drove to completion", decide (st.phase = .complete))
    , ("ECDHE shared secret (orchestrator handle) = RFC 8448", getEq st1.handles.shared ecdhe)
    , ("Handshake Secret (orchestrator handle) = RFC 8448", getEq st1.handles.handshake handshake)
    , ("server_handshake_traffic_secret (orchestrator handle) = RFC 8448", getEq st1.handles.sHs sHs)
    , ("Master Secret (orchestrator handle) = RFC 8448", getEq st.handles.master master)
    , ("server_application_traffic_secret_0 (orchestrator handle) = RFC 8448", getEq st.handles.sAp sAp)
    , ("installed server handshake write_key = RFC 8448", installedKeyEq .write .handshake sHsKey)
    , ("installed server handshake write_iv = RFC 8448", installedIvEq .write .handshake sHsIv)
    , ("client handshake keys installed (read/handshake)", installedPresent .read .handshake)
    , ("server application keys installed (write/application)", installedPresent .write .application)
    , ("client application keys installed (read/application)", installedPresent .read .application)
    ]
  return checks

def main : IO UInt32 := do
  IO.println "kroopt verified orchestrator driving the real provider through RFC 8448 §3:"
  match runChecks with
  | .error e =>
      IO.println s!"  FAIL  crypto/orchestrator error: {repr e}"
      IO.println "\n1 of 1 checks FAILED."; return 1
  | .ok checks =>
      let mut failures := 0
      for (name, ok) in checks do
        if ok then IO.println s!"  PASS  {name}"
        else IO.println s!"  FAIL  {name}"; failures := failures + 1
      if failures == 0 then
        IO.println s!"\nAll {checks.length} checks passed."; return 0
      else
        IO.println s!"\n{failures} of {checks.length} checks FAILED."; return 1

end Tests.ScheduleDriver

def main : IO UInt32 := Tests.ScheduleDriver.main
