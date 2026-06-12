import Kroopt.Conn.Flight
import Kroopt.Crypto.Hacl

/-!
# Tests.Flight

Validates the real server-flight assembler (`Kroopt.Conn.Flight`) — the
interpreter-side component that turns negotiated parameters and real HACL crypto
outputs into exact TLS 1.3 wire bytes. Covers:

* a **real Ed25519 CertificateVerify** produced by kroopt's own key: the RFC 8446
  §4.4.3 content construction (the OpenSSL-cross-validated one), sign/verify
  round-trip, and rejection of a wrong hash or wrong key;
* the **server Finished** MAC derivation anchored to RFC 8448 §3;
* the **ServerHello** assembly anchored to RFC 8448 §3;
* the Ed25519 key derivation anchored to the RFC 8032 §7.1 KAT.
-/

namespace Tests.Flight

open Kroopt.Conn
open Kroopt.Crypto

def hx (s : String) : ByteArray := Id.run do
  let cs := (s.toList.filter (fun (c : Char) => c ≠ ' ')).toArray
  let hv : Char → UInt8 := fun (c : Char) =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8 else 0
  let mut out : ByteArray := ByteArray.empty
  let mut i : Nat := 0
  while i + 1 < cs.size do
    out := out.push (hv cs[i]! * 16 + hv cs[i+1]!); i := i + 2
  return out

def eqB (a b : ByteArray) : Bool := a.toList == b.toList

-- RFC 8032 §7.1 Test 1 Ed25519 key (provenance: RFC 8032, used as kroopt's cert key here).
def certSeed : ByteArray := hx "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
def certPubExpected : ByteArray := hx "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
def otherSeed : ByteArray := hx "9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f0"

-- RFC 8448 §3 ServerHello parameters + expected bytes.
def serverRandom   : ByteArray := hx "a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28"
def serverKeyShare : ByteArray := hx "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f"
def rfcServerHello : ByteArray := hx
  "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04"
-- RFC 8448 §3 server-Finished key derivation.
def serverHsTraffic   : ByteArray := hx "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
def serverFinishedKey : ByteArray := hx "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8"

def main : IO UInt32 := do
  -- A representative transcript hash (CH‥Certificate would feed CertificateVerify).
  let th  := Hacl.sha256 (String.toUTF8 "kroopt server flight: CH..Certificate")
  let th2 := Hacl.sha256 (String.toUTF8 "kroopt server flight: a different transcript")
  let certPub := Hacl.ed25519Public certSeed

  -- (1) Ed25519 key matches the RFC 8032 KAT.
  let keyKat := eqB certPub certPubExpected

  -- (2) CertificateVerify signed-content construction (RFC 8446 §4.4.3).
  let content := Flight.certVerifyContent th
  let label := String.toUTF8 "TLS 1.3, server CertificateVerify"
  let contentSized := content.size == 130                       -- 64 + 33 + 1 + 32
  let contentSpaces := (content.extract 0 64).toList.all (fun (b : UInt8) => b == 0x20)
  let contentLabel := eqB (content.extract 64 97) label
  let contentSep := content.get! 97 == 0x00
  let contentHash := eqB (content.extract 98 130) th

  -- (3) Real Ed25519 CertificateVerify sign/verify round-trip.
  let sig := Flight.signCertVerify certSeed th
  let sigSized := sig.size == 64
  let verifyOk := Flight.verifyCertVerify certPub th sig == true
  let rejectsWrongHash := Flight.verifyCertVerify certPub th (Flight.signCertVerify certSeed th2) == false
  let rejectsWrongKey  := Flight.verifyCertVerify (Hacl.ed25519Public otherSeed) th sig == false

  -- (4) CertificateVerify message framing (type 0f, scheme 08 07, 64-byte sig).
  let cv := Flight.certificateVerifyMessage certSeed th
  let cvFramed := cv.size == 72 && cv.get! 0 == 0x0f && cv.get! 4 == 0x08 && cv.get! 5 == 0x07
                  && cv.get! 6 == 0x00 && cv.get! 7 == 0x40

  -- (5) ServerHello assembly matches RFC 8448 §3.
  let sh := Flight.serverHelloMessage serverRandom serverKeyShare 0x1301 0x001d 0x0304
  let shKat := eqB sh rfcServerHello

  -- (6) Server Finished key derivation matches RFC 8448 §3.
  let finKeyKat := eqB (Kroopt.Crypto.KeySchedule.finishedKey serverHsTraffic) serverFinishedKey

  -- (7) Server Finished message wraps HMAC(finished_key, transcript_hash).
  let fin := Flight.serverFinishedMessage serverHsTraffic th
  let vd := Flight.serverFinishedVerifyData serverHsTraffic th
  let finWraps := fin.size == 36 && fin.get! 0 == 0x14 && fin.get! 3 == 0x20
                  && eqB (fin.extract 4 36) vd

  let checks : List (String × Bool) :=
    [ ("Ed25519 cert key matches RFC 8032 §7.1 KAT", keyKat)
    , ("CertificateVerify content is 130 octets", contentSized)
    , ("CertificateVerify content begins with 64 space octets", contentSpaces)
    , ("CertificateVerify content carries the RFC 8446 context string", contentLabel)
    , ("CertificateVerify content has the 0x00 separator", contentSep)
    , ("CertificateVerify content ends with the transcript hash", contentHash)
    , ("real Ed25519 CertificateVerify signature is 64 octets", sigSized)
    , ("kroopt verifies its own CertificateVerify signature", verifyOk)
    , ("CertificateVerify verify rejects a wrong transcript hash", rejectsWrongHash)
    , ("CertificateVerify verify rejects a wrong key", rejectsWrongKey)
    , ("CertificateVerify message framing (0f / 08 07 / 64-byte sig)", cvFramed)
    , ("ServerHello assembly matches RFC 8448 §3", shKat)
    , ("server finished_key matches RFC 8448 §3", finKeyKat)
    , ("server Finished wraps HMAC(finished_key, transcript_hash)", finWraps)
    ]

  let mut failed := 0
  IO.println "kroopt real server-flight assembler checks (Ed25519 CertVerify + Finished + RFC 8448/8032):"
  for (name, ok) in checks do
    IO.println s!"  {if ok then "PASS" else "FAIL"}  {name}"
    if !ok then failed := failed + 1
  IO.println ""
  if failed == 0 then
    IO.println s!"All {checks.length} checks passed."
    pure 0
  else
    IO.println s!"{failed} of {checks.length} checks FAILED."
    pure 1

end Tests.Flight

def main : IO UInt32 := Tests.Flight.main
