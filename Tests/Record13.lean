import Kroopt.Conn.Record13
import Kroopt.Crypto.KeySchedule
import Kroopt.Crypto.Hacl

/-!
# Tests.Record13

Real TLS 1.3 record protection (`Kroopt.Conn.Record13`, ChaCha20-Poly1305): inner
plaintext framing, the §5.2 AAD, per-record nonce, and the outer `TLSCiphertext`
wrapping. Round-trip, structure, padding, content-type recovery, and the
authentication failures (tamper, wrong key, wrong sequence) that must yield no
plaintext.
-/

namespace Tests.Record13

open Kroopt.Conn
open Kroopt.Crypto
open Kroopt.Core (ContentType)

def eqB (a b : ByteArray) : Bool := a.toList == b.toList

-- A real derived ChaCha20-Poly1305 key/IV (provenance: RFC 8448 §3 server hs traffic).
def secret : ByteArray := Id.run do
  let s := "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
  let cs := s.toList.toArray
  let hv : Char → UInt8 := fun (c : Char) =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8 else 0
  let mut out : ByteArray := ByteArray.empty
  let mut i : Nat := 0
  while i + 1 < cs.size do
    out := out.push (hv cs[i]! * 16 + hv cs[i+1]!); i := i + 2
  return out

def key : ByteArray := KeySchedule.trafficKey .chacha20Poly1305Sha256 secret
def iv  : ByteArray := KeySchedule.trafficIv secret
def msg : ByteArray := String.toUTF8 "a TLS 1.3 handshake message payload"

def main : IO UInt32 := do
  let keySized := key.size == 32
  let ivSized  := iv.size == 12

  -- (1) handshake-record round-trip, no padding.
  let rec0 := Record13.sealRecord! key iv 0 msg .handshake 0
  let open0 := Record13.openRecord key iv 0 rec0
  let rt0 := match open0 with | some (c, t) => eqB c msg && t == ContentType.handshake | none => false

  -- (2) wire structure: outer application_data, 0x0303, length, tag-expanded size.
  let innerLen := msg.size + 1            -- content + inner content-type
  let ctLen := innerLen + 16             -- + Poly1305 tag
  let struct := rec0.get! 0 == 0x17 && rec0.get! 1 == 0x03 && rec0.get! 2 == 0x03
                && rec0.get! 3 == (ctLen / 256).toUInt8 && rec0.get! 4 == (ctLen % 256).toUInt8
                && rec0.size == 5 + ctLen

  -- (3) ciphertext is not the plaintext.
  let encrypted := !(eqB (rec0.extract 5 rec0.size) (Record13.innerPlaintext msg .handshake 0))

  -- (4) padding is stripped on open.
  let recPad := Record13.sealRecord! key iv 0 msg .handshake 17
  let rtPad := match Record13.openRecord key iv 0 recPad with
               | some (c, t) => eqB c msg && t == ContentType.handshake | none => false

  -- (5) application_data content type round-trips.
  let recApp := Record13.sealRecord! key iv 0 msg .applicationData 0
  let rtApp := match Record13.openRecord key iv 0 recApp with
               | some (_, t) => t == ContentType.applicationData | none => false

  -- (6) a tampered record fails to open (no plaintext escapes).
  let tampered := rec0.set! (rec0.size - 1) ((rec0.get! (rec0.size - 1)) ^^^ 0xFF)
  let tamperRejected := (Record13.openRecord key iv 0 tampered).isNone

  -- (7) the wrong key fails to open.
  let wrongKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 (Hacl.sha256 secret)
  let wrongKeyRejected := (Record13.openRecord wrongKey iv 0 rec0).isNone

  -- (8) the sequence number binds the nonce: seq 1 differs, and opening rec0 at
  -- the wrong sequence fails.
  let rec1 := Record13.sealRecord! key iv 1 msg .handshake 0
  let seqBindsCiphertext := !(eqB rec0 rec1)
  let wrongSeqRejected := (Record13.openRecord key iv 1 rec0).isNone

  let checks : List (String × Bool) :=
    [ ("derived ChaCha20-Poly1305 key is 32 octets", keySized)
    , -- RFC 037 §5: content above the 2^14 record bound is rejected (typed resourceLimit error),
      -- never sealed through the truncating UInt16 length cast; content at the bound still seals.
      ("oversize content is rejected by sealRecord (RFC 037 §5)",
        (match Record13.sealRecord key iv 0 (ByteArray.mk (Array.mkArray 16385 (0:UInt8))) .applicationData 0 with
         | .error .recordSize => true | _ => false))
    , ("content at the 2^14 bound still seals (RFC 037 §5)",
        (match Record13.sealRecord key iv 0 (ByteArray.mk (Array.mkArray 16384 (0:UInt8))) .applicationData 0 with
         | .ok _ => true | _ => false))
    , ("derived record IV is 12 octets", ivSized)
    , ("handshake record round-trips (content + inner type)", rt0)
    , ("record is a TLSCiphertext: 0x17 0x0303, length, tag-expanded size", struct)
    , ("record body is ciphertext, not the plaintext", encrypted)
    , ("inner-plaintext padding is stripped on open", rtPad)
    , ("application_data inner content type round-trips", rtApp)
    , ("a tampered record fails to open (no plaintext escapes)", tamperRejected)
    , ("the wrong key fails to open", wrongKeyRejected)
    , ("the sequence number binds the nonce (seq 1 differs)", seqBindsCiphertext)
    , ("opening at the wrong sequence fails", wrongSeqRejected)
    ]

  let mut failed := 0
  IO.println "kroopt real TLS 1.3 record protection (ChaCha20-Poly1305):"
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

end Tests.Record13

def main : IO UInt32 := Tests.Record13.main
