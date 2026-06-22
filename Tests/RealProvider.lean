import Tests.RealFixtures
import Kroopt.Crypto.RealProvider
import Kroopt.Crypto.Provider
import Kroopt.Crypto.Arena
import Kroopt.Crypto.KeySchedule
import Kroopt.Crypto.Hacl
import Kroopt.Crypto.CertLint
import Kroopt.Core.Crypto
import Kroopt.Core.Record
import Kroopt.Core.Id

/-!
# Tests.RealProvider

Validates the real `CryptoProvider` (`Kroopt.Crypto.mkRealProvider`) by driving it
through the **RFC 8448 §3 key-schedule operation sequence via `submit`** — the
same calls, in the same order, that the verified core will eventually emit. Every
secret produced lands in the arena under an opaque handle and is read back and
compared to the published RFC 8448 value; the install path is checked against the
RFC's AES traffic key/IV; and the AEAD, signature, and Finished paths are
exercised with real HACL* cryptography. This shows the provider seam can perform a
real TLS 1.3 handshake's cryptography.
-/

namespace Tests.RealProvider

open Kroopt.Crypto
open Kroopt.Core (CryptoOp CryptoResult RecordCryptoMeta Direction Epoch CipherSuite SignatureScheme)

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
def serverPub  := "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"
def ecdhe      := "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
def early      := "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
def derivedHs  := "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
def handshake  := "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
def th1        := "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
def cHs        := "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
def sHs        := "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
def derivedMs  := "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"
def master     := "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
def th2        := "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
def sAp        := "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
def sHsKey     := "3fce516009c21727d0f2e4e86ee403bc"
def sHsIv      := "5d313eb2671276ee13000b30"

def emptyHashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/-- Run the whole sequence through `submit`, returning labelled boolean checks.
A crypto error anywhere collapses to a single failed check. -/
def runChecks : Except Kroopt.CryptoError (List (String × Bool)) := do
  let certPriv := hexToBytes "9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f"
  let certPub := Kroopt.Crypto.Hacl.ed25519Public certPriv
  let cfg : RealCryptoConfig :=
    { ephemeralPrivate := hexToBytes serverPriv, certPrivate := certPriv, certPublic := certPub }
  let p := RealProvider.submit cfg
  let a := SecretArena.empty
  let oid := (⟨0⟩ : Kroopt.Core.OperationId)
  let emptyHash := hexToBytes emptyHashHex

  -- ECDHE
  let (a, r) ← p a oid (.ecdheX25519 (hexToBytes clientPub))
  let .ecdheComplete srvShare sharedH := r | throw .providerInternal
  -- Early Secret = Extract(0,0)
  let (a, r) ← p a oid (.hkdfExtract .sha256 none none)
  let .hkdfSecret earlyH := r | throw .providerInternal
  -- derived = Expand-Label(early, "derived", emptyHash)
  let (a, r) ← p a oid (.hkdfExpandLabel .sha256 earlyH "derived" emptyHash 32)
  let .hkdfSecret derivedH := r | throw .providerInternal
  -- Handshake Secret = Extract(derived, ecdhe)
  let (a, r) ← p a oid (.hkdfExtract .sha256 (some derivedH) (some sharedH))
  let .hkdfSecret hsH := r | throw .providerInternal
  -- server/client handshake traffic secrets = Expand-Label(HS, "_ hs traffic", th1)
  let (a, r) ← p a oid (.hkdfExpandLabel .sha256 hsH "s hs traffic" (hexToBytes th1) 32)
  let .hkdfSecret sHsH := r | throw .providerInternal
  let (a, r) ← p a oid (.hkdfExpandLabel .sha256 hsH "c hs traffic" (hexToBytes th1) 32)
  let .hkdfSecret cHsH := r | throw .providerInternal
  -- derived2 = Expand-Label(HS, "derived", emptyHash); Master = Extract(derived2, 0)
  let (a, r) ← p a oid (.hkdfExpandLabel .sha256 hsH "derived" emptyHash 32)
  let .hkdfSecret derivedMsH := r | throw .providerInternal
  let (a, r) ← p a oid (.hkdfExtract .sha256 (some derivedMsH) none)
  let .hkdfSecret msH := r | throw .providerInternal
  -- server application traffic secret = Expand-Label(MS, "s ap traffic", th2)
  let (a, r) ← p a oid (.hkdfExpandLabel .sha256 msH "s ap traffic" (hexToBytes th2) 32)
  let .hkdfSecret sApH := r | throw .providerInternal

  -- install AES handshake keys for (read, handshake) to check against RFC 8448 key/iv
  let (a, _) ← p a oid (.installTrafficKeys .aes128GcmSha256 .read .handshake sHsH)
  let aesKeyIv := a.lookupInstalled .read .handshake
  let aesKeyOk := match aesKeyIv with
    | some (k, _) => match a.getById k with | some kb => eqB kb (hexToBytes sHsKey) | none => false
    | none => false
  let aesIvOk := match aesKeyIv with
    | some (_, iv) => match a.getById iv with | some ib => eqB ib (hexToBytes sHsIv) | none => false
    | none => false

  -- install ChaCha20-Poly1305 keys for (write, handshake) and round-trip a record
  let (a, _) ← p a oid (.installTrafficKeys .chacha20Poly1305Sha256 .write .handshake sHsH)
  let meta : RecordCryptoMeta :=
    { conn := ⟨0,0⟩, direction := .write, epoch := .handshake, seq := ⟨0⟩,
      suite := .chacha20Poly1305Sha256, contentRole := .applicationData }
  let aad := hexToBytes "1703030010"
  let pt := hexToBytes "48656c6c6f2c20545453"
  let (a, rs) ← p a oid (.aeadSeal meta aad pt)
  let .aeadSealed ct := rs | throw .providerInternal
  let (a, ro) ← p a oid (.aeadOpen meta aad ct)
  let aeadRoundTrip := match ro with | .aeadOpened opened => eqB opened pt | _ => false
  let (a, rt) ← p a oid (.aeadOpen meta aad (ct.set! 0 ((ct.get! 0) ^^^ 1)))
  let aeadTamper := match rt with | .verifyFailed => true | _ => false

  -- real Ed25519 CertificateVerify signature, verified with the cert public key
  let msg := hexToBytes "deadbeefcafe"
  let (a, rsig) ← p a oid (.signCertificateVerify .ed25519 msg)
  let signOk := match rsig with
    | .signature sig => Kroopt.Crypto.Hacl.ed25519Verify certPub msg sig | _ => false

  -- real ECDSA P-256 CertificateVerify: the provider dispatches to ecdsaP256SignDer and returns a
  -- DER-encoded Ecdsa-Sig-Value (RFC 8446 §4.4.3). Crypto correctness is KAT-proven in Tests.Hacl;
  -- here we confirm the provider wiring and the on-the-wire DER shape.
  let ecdsaCfg : RealCryptoConfig :=
    { ephemeralPrivate := hexToBytes serverPriv, certPrivate := ByteArray.empty
      ecdsaPriv := hexToBytes "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
      certPublic := ByteArray.empty
      signNonce := hexToBytes "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de" }
  let (_, recdsa) ← (RealProvider.submit ecdsaCfg) a oid (.signCertificateVerify .ecdsaSecp256r1Sha256 msg)
  let ecdsaSigOk := match recdsa with
    | .signature der =>
        der.size ≥ 8 ∧ der.get! 0 == 0x30 ∧ der.size == (der.get! 1).toNat + 2 ∧ der.get! 2 == 0x02
    | _ => false

  -- real RSA-PSS CertificateVerify: the provider dispatches to rsapssSign with the RSA key and the
  -- per-connection salt; the raw RSA signature verifies against the public key (round-trip).
  let rsaSalt := hexToBytes "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
  let rsaCfg2 : RealCryptoConfig :=
    { ephemeralPrivate := hexToBytes serverPriv, certPrivate := ByteArray.empty
      certPublic := ByteArray.empty, signNonce := rsaSalt
      rsaN := Tests.RealFixtures.rsaN, rsaE := Tests.RealFixtures.rsaE, rsaD := Tests.RealFixtures.rsaD }
  let (_, rrsa) ← (RealProvider.submit rsaCfg2) a oid (.signCertificateVerify .rsaPssRsaeSha256 msg)
  let rsaSigOk := match rrsa with
    | .signature sig =>
        sig.size == 256 ∧ Kroopt.Crypto.Hacl.rsapssVerify Tests.RealFixtures.rsaN Tests.RealFixtures.rsaE 32 sig msg
    | _ => false

  -- Finished: provider derives finished_key from the handshake base secret
  let finKey := KeySchedule.finishedKey (hexToBytes sHs)
  let goodMac := Kroopt.Crypto.Hacl.hmac256 finKey (hexToBytes th2)
  let (a, rf) ← p a oid (.verifyFinished .sha256 (hexToBytes th2) goodMac)
  let finishedOk := match rf with | .verified => true | _ => false
  let (a, rf2) ← p a oid (.verifyFinished .sha256 (hexToBytes th2) (hexToBytes th1))
  let finishedRejects := match rf2 with | .verifyFailed => true | _ => false

  let getEq : Kroopt.Core.SecretKeyHandle → String → Bool :=
    fun h hex => (match a.get h with | some b => eqB b (hexToBytes hex) | none => false)

  let checks : List (String × Bool) :=
    [ ("ECDHE returns server public share = RFC 8448 server_pub", eqB srvShare (hexToBytes serverPub))
    , ("ECDHE shared secret (in arena) = RFC 8448 shared", getEq sharedH ecdhe)
    , ("Early Secret (in arena) = RFC 8448", getEq earlyH early)
    , ("Derive-Secret(Early,\"derived\") (in arena) = RFC 8448", getEq derivedH derivedHs)
    , ("Handshake Secret (in arena) = RFC 8448", getEq hsH handshake)
    , ("server_handshake_traffic_secret (in arena) = RFC 8448", getEq sHsH sHs)
    , ("client_handshake_traffic_secret (in arena) = RFC 8448", getEq cHsH cHs)
    , ("Derive-Secret(HS,\"derived\") (in arena) = RFC 8448", getEq derivedMsH derivedMs)
    , ("Master Secret (in arena) = RFC 8448", getEq msH master)
    , ("server_application_traffic_secret_0 (in arena) = RFC 8448", getEq sApH sAp)
    , ("installTrafficKeys derives RFC 8448 server handshake write_key", aesKeyOk)
    , ("installTrafficKeys derives RFC 8448 server handshake write_iv", aesIvOk)
    , ("AEAD seal+open round-trips through installed key", aeadRoundTrip)
    , ("AEAD open of a tampered record returns verifyFailed", aeadTamper)
    , ("CertificateVerify Ed25519 signature verifies", signOk)
    , ("CertificateVerify ECDSA-P256 produces a DER Ecdsa-Sig-Value", ecdsaSigOk)
    , ("CertificateVerify RSA-PSS signature verifies (round-trip)", rsaSigOk)
    , ("verifyFinished accepts the correct Finished MAC", finishedOk)
    , ("verifyFinished rejects a wrong Finished MAC", finishedRejects)
    , ("cert-lint: Ed25519 leaf public key matches the configured seed (RFC 011 §11.2)",
        Kroopt.Crypto.CertLint.ed25519KeyMatches Tests.RealFixtures.certDer Tests.RealFixtures.certSeed)
    , ("cert-lint: EC P-256 leaf public point matches the configured scalar",
        Kroopt.Crypto.CertLint.ecP256KeyMatches Tests.RealFixtures.ecdsaCertDer Tests.RealFixtures.ecdsaCertPriv)
    , ("cert-lint: a mismatched Ed25519 private key is rejected",
        !Kroopt.Crypto.CertLint.ed25519KeyMatches Tests.RealFixtures.certDer Tests.RealFixtures.ecdsaCertPriv)
    , ("cert-lint: an Ed25519 check against an EC certificate is rejected (no Ed25519 SPKI)",
        !Kroopt.Crypto.CertLint.ed25519KeyMatches Tests.RealFixtures.ecdsaCertDer Tests.RealFixtures.certSeed)
    ]
  return checks

def main : IO UInt32 := do
  IO.println "kroopt real CryptoProvider driven through the RFC 8448 §3 handshake via submit:"
  match runChecks with
  | .error e =>
      IO.println s!"  FAIL  crypto error during the op sequence: {repr e}"
      IO.println "\n1 of 1 checks FAILED."
      return 1
  | .ok checks =>
      let mut failures := 0
      for (name, ok) in checks do
        if ok then IO.println s!"  PASS  {name}"
        else IO.println s!"  FAIL  {name}"; failures := failures + 1
      if failures == 0 then
        IO.println s!"\nAll {checks.length} checks passed."; return 0
      else
        IO.println s!"\n{failures} of {checks.length} checks FAILED."; return 1

end Tests.RealProvider

def main : IO UInt32 := Tests.RealProvider.main
