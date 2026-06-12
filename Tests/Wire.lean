import Kroopt.Parse.Wire
import Kroopt.Parse.Handshake
import Kroopt.Crypto.Hacl

/-!
# Tests.Wire

Validates the TLS 1.3 handshake wire serializer (`Kroopt.Parse.Wire`) against the
**RFC 8448 §3 "Simple 1-RTT Handshake"** trace (provenance: RFC 8448, Section 3,
fetched from rfc-editor.org). The decisive check closes the structural→real
transcript loop: `SHA-256(ClientHello ‖ serialized ServerHello)` equals the
RFC 8448 CH‥ServerHello transcript hash the key schedule derives handshake
traffic secrets over. Also exercises the existing ClientHello parser against the
real RFC 8448 ClientHello.
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

-- RFC 8448 §3 vectors (verbatim, Section 3 "Simple 1-RTT Handshake").
def rfcClientHello : ByteArray := hx
  "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"

def rfcServerHello : ByteArray := hx
  "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04"

def serverRandom   : ByteArray := hx "a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28"
def serverKeyShare : ByteArray := hx "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f"
def clientKeyShare : ByteArray := hx "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c"
-- RFC 8448 §3: the "tls13 {c,s} hs traffic" derivation hash = Transcript-Hash(CH‖SH).
def chshTranscriptHash : ByteArray := hx "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"

def main : IO UInt32 := do
  -- Serialize ServerHello from the RFC 8448 negotiated parameters.
  let sh := Wire.serverHello serverRandom ByteArray.empty 0x1301 0x001d serverKeyShare 0x0304
  let shExact := eqB sh rfcServerHello
  let shSized := sh.size == 90
  let shTyped := sh.size > 0 && sh.get! 0 == 0x02
  -- ServerHello length field (3 bytes) equals body size (90 - 4 = 86 = 0x56).
  let shLenField := sh.size ≥ 4 && sh.get! 1 == 0x00 && sh.get! 2 == 0x00 && sh.get! 3 == 0x56

  -- Decisive: real transcript hash over real wire bytes matches RFC 8448.
  let th := Kroopt.Crypto.Hacl.sha256 (rfcClientHello ++ sh)
  let thMatch := eqB th chshTranscriptHash
  -- Sanity: the serialized SH is what produced it (hash over rfcServerHello agrees).
  let thMatch2 := eqB (Kroopt.Crypto.Hacl.sha256 (rfcClientHello ++ rfcServerHello)) chshTranscriptHash

  -- The existing parser accepts the real RFC 8448 ClientHello and extracts its share.
  let parsed := Kroopt.Parse.parseClientHello rfcClientHello
  let parseOk := match parsed with | .ok _ => true | .error _ => false
  let shareOk := match parsed with
    | .ok wb => eqB wb.value.clientShare clientKeyShare
    | .error _ => false

  -- A handful of builder invariants.
  let ee := Wire.encryptedExtensions ByteArray.empty   -- 08 00 00 02 00 00
  let eeOk := eqB ee (hx "08 00 00 02 00 00")
  let finOk := (Wire.finished (hx "00 01 02 03")).size == 8   -- 4 header + 4 verify_data
  let be16Ok := eqB (Wire.be16 0x0304) (hx "03 04")

  let checks : List (String × Bool) :=
    [ ("ServerHello serializes byte-for-byte to RFC 8448 §3", shExact)
    , ("ServerHello is 90 octets", shSized)
    , ("ServerHello handshake type is 0x02", shTyped)
    , ("ServerHello length field encodes the 86-byte body (0x000056)", shLenField)
    , ("SHA-256(CH ‖ serialized SH) = RFC 8448 CH‥SH transcript hash", thMatch)
    , ("SHA-256(CH ‖ RFC SH) = RFC 8448 CH‥SH transcript hash", thMatch2)
    , ("parser accepts the real RFC 8448 ClientHello", parseOk)
    , ("parser extracts the RFC 8448 client x25519 key_share", shareOk)
    , ("EncryptedExtensions(empty) = 08 00 00 02 00 00", eeOk)
    , ("Finished wraps verify_data with a 4-byte header", finOk)
    , ("be16 encodes 0x0304 big-endian", be16Ok)
    ]

  let mut failed := 0
  IO.println "kroopt TLS 1.3 wire serialization KATs (RFC 8448 §3):"
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
