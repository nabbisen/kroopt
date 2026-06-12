import Kroopt.Parse.Wire
import Kroopt.Parse.Handshake
import Kroopt.Crypto.Hacl
import Kroopt.Crypto.KeySchedule

/-!
# Tests.Wire

Validates the TLS 1.3 handshake wire serializer (`Kroopt.Parse.Wire`) against the
**RFC 8448 §3 "Simple 1-RTT Handshake"** trace (provenance: RFC 8448, Section 3,
fetched from rfc-editor.org).

Two kinds of check:

* **Framing** — every server-flight message (ServerHello, EncryptedExtensions,
  Certificate, CertificateVerify, Finished) serializes byte-for-byte to the RFC
  8448 bytes. The Certificate/CertificateVerify use RSA, which the vendored HACL
  subset cannot produce, so their crypto blobs are sliced from the RFC vector and
  fed back as opaque inputs — this validates the *framing*, not the RSA math.
* **Real crypto KATs** — `SHA-256(ClientHello ‖ serialized ServerHello)` equals
  the RFC 8448 CH‥SH transcript hash; and the **server Finished verify_data**,
  recomputed as `HMAC(finished_key, Transcript-Hash(CH‥CertificateVerify))` over
  the serialized flight, equals the RFC 8448 value. HMAC/SHA-256 are real here.
-/

namespace Tests.Wire

open Kroopt.Parse

/-- Hex → bytes, ignoring ASCII spaces (so RFC byte groups paste verbatim). -/
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

-- ── RFC 8448 §3 vectors (verbatim, Section 3 "Simple 1-RTT Handshake") ──
def rfcClientHello : ByteArray := hx
  "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"

def rfcServerHello : ByteArray := hx
  "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04"

def rfcEncExt : ByteArray := hx
  "08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c 00 02 40 01 00 00 00 00"

def rfcCertificate : ByteArray := hx
  "0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00"

def rfcCertVerify : ByteArray := hx
  "0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3"

def rfcFinished : ByteArray := hx
  "14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18"

def serverRandom   : ByteArray := hx "a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28"
def serverKeyShare : ByteArray := hx "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f"
def clientKeyShare : ByteArray := hx "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c"
-- RFC 8448 §3: "tls13 {c,s} hs traffic" derivation hash = Transcript-Hash(CH‖SH).
def chshTranscriptHash : ByteArray := hx "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"
-- RFC 8448 §3 server-side Finished inputs/outputs.
def serverHsTraffic    : ByteArray := hx "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
def serverFinishedKey  : ByteArray := hx "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8"
def serverVerifyData   : ByteArray := hx "9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18"

def main : IO UInt32 := do
  -- ── serialize the server flight from RFC 8448 parameters ──
  let sh := Wire.serverHello serverRandom ByteArray.empty 0x1301 0x001d serverKeyShare 0x0304
  let ee := Wire.encryptedExtensions (rfcEncExt.extract 6 40)              -- 34-byte ext block
  let certDer := rfcCertificate.extract 11 443                              -- 432-byte DER leaf
  let cert := Wire.certificate ByteArray.empty (Wire.certificateEntry certDer ByteArray.empty)
  let cvSig := rfcCertVerify.extract 8 136                                  -- 128-byte RSA-PSS sig
  let cv := Wire.certificateVerify 0x0804 cvSig
  let fin := Wire.finished (rfcFinished.extract 4 36)                       -- 32-byte verify_data

  -- ── framing: each message is byte-for-byte the RFC 8448 message ──
  let shExact   := eqB sh rfcServerHello
  let eeExact   := eqB ee rfcEncExt
  let certExact := eqB cert rfcCertificate
  let cvExact   := eqB cv rfcCertVerify
  let finExact  := eqB fin rfcFinished
  let shSized   := sh.size == 90 && sh.get! 0 == 0x02
  let shLenFld  := sh.size ≥ 4 && sh.get! 1 == 0x00 && sh.get! 2 == 0x00 && sh.get! 3 == 0x56

  -- ── real crypto: CH‥SH transcript hash ──
  let thCHSH := Kroopt.Crypto.Hacl.sha256 (rfcClientHello ++ sh)
  let thCHSHok := eqB thCHSH chshTranscriptHash

  -- ── real crypto: server Finished MAC over the serialized flight ──
  -- finished_key = HKDF-Expand-Label(server_hs_traffic, "finished", "", 32)
  let finKey := Kroopt.Crypto.KeySchedule.finishedKey serverHsTraffic
  let finKeyOk := eqB finKey serverFinishedKey
  -- verify_data = HMAC(finished_key, Transcript-Hash(CH ‖ SH ‖ EE ‖ Cert ‖ CertVerify))
  let thCertVerify := Kroopt.Crypto.Hacl.sha256 (rfcClientHello ++ sh ++ ee ++ cert ++ cv)
  let verifyData := Kroopt.Crypto.Hacl.hmac256 finKey thCertVerify
  let verifyDataOk := eqB verifyData serverVerifyData
  -- and that the Finished message wraps exactly that verify_data
  let finWraps := eqB (Wire.finished verifyData) rfcFinished

  -- ── parser accepts the real RFC 8448 ClientHello ──
  let parsed := Kroopt.Parse.parseClientHello rfcClientHello
  let parseOk := match parsed with | .ok _ => true | .error _ => false
  let shareOk := match parsed with
    | .ok wb => eqB wb.value.clientShare clientKeyShare
    | .error _ => false

  let checks : List (String × Bool) :=
    [ ("ServerHello serializes byte-for-byte to RFC 8448 §3", shExact)
    , ("ServerHello is 90 octets, type 0x02", shSized)
    , ("ServerHello length field encodes the 86-byte body (0x000056)", shLenFld)
    , ("EncryptedExtensions serializes byte-for-byte to RFC 8448 §3", eeExact)
    , ("Certificate framing serializes byte-for-byte to RFC 8448 §3 (RSA leaf opaque)", certExact)
    , ("CertificateVerify framing serializes byte-for-byte to RFC 8448 §3 (RSA-PSS sig opaque)", cvExact)
    , ("Finished serializes byte-for-byte to RFC 8448 §3", finExact)
    , ("SHA-256(CH ‖ serialized SH) = RFC 8448 CH‥SH transcript hash", thCHSHok)
    , ("finished_key = HKDF-Expand-Label(s hs traffic, finished) matches RFC 8448", finKeyOk)
    , ("server Finished verify_data = HMAC(finished_key, Transcript-Hash(CH‥CertVerify)) matches RFC 8448", verifyDataOk)
    , ("Finished message wraps the recomputed verify_data", finWraps)
    , ("parser accepts the real RFC 8448 ClientHello", parseOk)
    , ("parser extracts the RFC 8448 client x25519 key_share", shareOk)
    ]

  let mut failed := 0
  IO.println "kroopt TLS 1.3 wire serialization + server-Finished KATs (RFC 8448 §3):"
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

end Tests.Wire

def main : IO UInt32 := Tests.Wire.main
