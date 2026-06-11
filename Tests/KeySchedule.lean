import Kroopt.Crypto.KeySchedule
import Kroopt.Crypto.Real
import Kroopt.Crypto.Arena
import Kroopt.Crypto.Hacl
import Kroopt.Core.Record
import Kroopt.Core.Crypto
import Kroopt.Core.Id

/-!
# Tests.KeySchedule

Validates the real TLS 1.3 key schedule (`Kroopt.Crypto.KeySchedule`) end-to-end
against the **RFC 8448 §3** "Simple 1-RTT Handshake" trace, computed on the
native HACL* primitives — every secret in the chain (early → handshake → master,
the handshake/application traffic secrets, traffic keys/IVs, and the Finished
key) matches the published values. Then it drives a real key through the
`SecretArena` into the ChaCha20-Poly1305 AEAD (`Kroopt.Crypto.Real`) to show real
key material flowing from derivation to record protection, with arena
generation/stale-handle behaviour checked.
-/

namespace Tests.KeySchedule

open Kroopt.Crypto.KeySchedule
open Kroopt.Crypto (SecretArena)
open Kroopt.Core (RecordCryptoMeta ConnId SeqNo Direction Epoch CipherSuite RecordContentRole)

structure Check where
  name : String
  ok : Bool

def hexToBytes (s : String) : ByteArray := Id.run do
  let cs := s.toList.toArray
  let hexVal : Char → UInt8 := fun c =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8
    else if 'A' ≤ c ∧ c ≤ 'F' then (c.toNat - 'A'.toNat + 10).toUInt8
    else 0
  let mut out : ByteArray := ByteArray.empty
  let mut i := 0
  while i + 1 < cs.size do
    out := out.push (hexVal cs[i]! * 16 + hexVal cs[i+1]!)
    i := i + 2
  return out

def bytesEq (a b : ByteArray) : Bool := a.toList == b.toList

-- RFC 8448 §3 vectors (TLS_AES_128_GCM_SHA256, X25519, SHA-256)
def v_clientPriv := "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
def v_clientPub  := "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
def v_serverPriv := "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
def v_serverPub  := "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"
def v_ecdhe      := "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
def v_early      := "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
def v_emptyHash  := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
def v_derivedHs  := "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
def v_handshake  := "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
def v_th1        := "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
def v_cHs        := "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
def v_sHs        := "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
def v_derivedMs  := "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"
def v_master     := "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
def v_th2        := "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
def v_cAp        := "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
def v_sAp        := "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
def v_sHsKey     := "3fce516009c21727d0f2e4e86ee403bc"
def v_sHsIv      := "5d313eb2671276ee13000b30"
def v_sHsFin     := "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
def v_sApKey     := "9f02283b6c9c07efc26bb9f2ac92e356"
def v_cHsKey     := "dbfaa693d1762c5b666af5d950258d01"

def main : IO UInt32 := do
  let ecdhe := hexToBytes v_ecdhe
  -- compute the chain (composition exercised, not just point checks)
  let hs := handshakeSecret earlySecret ecdhe
  let ms := masterSecret hs
  let sHs := serverHandshakeTrafficSecret hs (hexToBytes v_th1)
  let cHs := clientHandshakeTrafficSecret hs (hexToBytes v_th1)
  let sAp := serverAppTrafficSecret ms (hexToBytes v_th2)

  -- arena AEAD round-trip with a real derived ChaCha20-Poly1305 key
  let aKey := trafficKey .chacha20Poly1305Sha256 sHs
  let aIv  := trafficIv sHs
  let meta : RecordCryptoMeta :=
    { conn := ⟨0, 0⟩, direction := .write, epoch := .handshake, seq := ⟨0⟩,
      suite := .chacha20Poly1305Sha256, contentRole := .applicationData }
  let aad := hexToBytes "1703030010"
  let pt  := hexToBytes "48656c6c6f2c20545453"
  let aeadOk : Bool :=
    match Kroopt.Crypto.Real.install SecretArena.empty (default : Kroopt.Crypto.Real.KeyStore)
            .write .handshake .chacha20Poly1305Sha256 aKey aIv with
    | .ok (arena, ks) =>
      match Kroopt.Crypto.Real.sealRecord arena ks meta aad pt with
      | .ok sealed =>
        (match Kroopt.Crypto.Real.openRecord arena ks meta aad sealed with
         | .ok opened => bytesEq opened pt | _ => false)
      | _ => false
    | _ => false
  let aeadTamperRejected : Bool :=
    match Kroopt.Crypto.Real.install SecretArena.empty (default : Kroopt.Crypto.Real.KeyStore)
            .write .handshake .chacha20Poly1305Sha256 aKey aIv with
    | .ok (arena, ks) =>
      match Kroopt.Crypto.Real.sealRecord arena ks meta aad pt with
      | .ok sealed =>
        (match Kroopt.Crypto.Real.openRecord arena ks meta aad (sealed.set! 0 ((sealed.get! 0) ^^^ 1)) with
         | .error _ => true | _ => false)
      | _ => false
    | _ => false

  -- arena store/get + stale-handle behaviour
  let arenaOk : Bool :=
    match SecretArena.empty.store (hexToBytes "0102030405") with
    | .ok (h, a1) =>
      let got := (a1.get h).map bytesEq |>.getD (fun _ => false)
      let live := got (hexToBytes "0102030405")
      let stale := ((a1.bumpGeneration).get h).isNone
      live ∧ stale
    | _ => false

  let checks : List Check :=
    [ { name := "empty transcript hash = SHA-256(\"\") (RFC 8448)"
      , ok := bytesEq emptyHash (hexToBytes v_emptyHash) }
    , { name := "Early Secret = HKDF-Extract(0,0) (RFC 8448)"
      , ok := bytesEq earlySecret (hexToBytes v_early) }
    , { name := "X25519 ECDH (server priv, client pub) = RFC 8448 shared"
      , ok := (match Kroopt.Crypto.Hacl.x25519Shared (hexToBytes v_serverPriv) (hexToBytes v_clientPub) with
               | some s => bytesEq s ecdhe | none => false) }
    , { name := "X25519 ECDH (client priv, server pub) = same shared"
      , ok := (match Kroopt.Crypto.Hacl.x25519Shared (hexToBytes v_clientPriv) (hexToBytes v_serverPub) with
               | some s => bytesEq s ecdhe | none => false) }
    , { name := "Derive-Secret(Early,\"derived\",\"\") (RFC 8448)"
      , ok := bytesEq (derivedForHandshake earlySecret) (hexToBytes v_derivedHs) }
    , { name := "Handshake Secret = HKDF-Extract(derived, ECDHE) (RFC 8448)"
      , ok := bytesEq hs (hexToBytes v_handshake) }
    , { name := "client_handshake_traffic_secret (RFC 8448)"
      , ok := bytesEq cHs (hexToBytes v_cHs) }
    , { name := "server_handshake_traffic_secret (RFC 8448)"
      , ok := bytesEq sHs (hexToBytes v_sHs) }
    , { name := "Derive-Secret(HS,\"derived\",\"\") for master (RFC 8448)"
      , ok := bytesEq (derivedForMaster hs) (hexToBytes v_derivedMs) }
    , { name := "Master Secret = HKDF-Extract(derived, 0) (RFC 8448)"
      , ok := bytesEq ms (hexToBytes v_master) }
    , { name := "client_application_traffic_secret_0 (RFC 8448)"
      , ok := bytesEq (clientAppTrafficSecret ms (hexToBytes v_th2)) (hexToBytes v_cAp) }
    , { name := "server_application_traffic_secret_0 (RFC 8448)"
      , ok := bytesEq sAp (hexToBytes v_sAp) }
    , { name := "server handshake write_key (key len 16) (RFC 8448)"
      , ok := bytesEq (trafficKey .aes128GcmSha256 sHs) (hexToBytes v_sHsKey) }
    , { name := "server handshake write_iv (RFC 8448)"
      , ok := bytesEq (trafficIv sHs) (hexToBytes v_sHsIv) }
    , { name := "server handshake finished_key (RFC 8448)"
      , ok := bytesEq (finishedKey sHs) (hexToBytes v_sHsFin) }
    , { name := "server application write_key (RFC 8448)"
      , ok := bytesEq (trafficKey .aes128GcmSha256 sAp) (hexToBytes v_sApKey) }
    , { name := "client handshake write_key (RFC 8448)"
      , ok := bytesEq (trafficKey .aes128GcmSha256 cHs) (hexToBytes v_cHsKey) }
    , { name := "arena AEAD: real derived key seals+opens a record round-trip"
      , ok := aeadOk }
    , { name := "arena AEAD: a tampered record fails to open"
      , ok := aeadTamperRejected }
    , { name := "arena: store/get round-trips; stale handle rejected after bump"
      , ok := arenaOk }
    ]

  let mut failures := 0
  IO.println "kroopt key schedule vs RFC 8448 §3, through HACL* + the secret arena:"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.KeySchedule

def main : IO UInt32 := Tests.KeySchedule.main
