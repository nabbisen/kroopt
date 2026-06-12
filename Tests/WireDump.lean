import Kroopt.Conn.Record13
import Kroopt.Crypto.KeySchedule

/-!
# Tests.WireDump

Emits real kroopt TLS 1.3 records (sealed by `Kroopt.Conn.Record13`) so an
independent implementation can decrypt them. Used by `scripts/record-interop.sh`,
which has Python's `cryptography` library derive the traffic key/IV from the secret
(RFC 8446 §7.3) and open the records — a cross-implementation check that kroopt's
record layer is standards-compliant, not just self-consistent.
-/

namespace Tests.WireDump

open Kroopt.Conn
open Kroopt.Crypto
open Kroopt.Core (ContentType)

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

def toHex (b : ByteArray) : String :=
  let d : Nat → Char := fun (n : Nat) =>
    if n < 10 then Char.ofNat (n + '0'.toNat) else Char.ofNat (n - 10 + 'a'.toNat)
  b.toList.foldl (fun (s : String) (x : UInt8) => (s.push (d (x.toNat / 16))).push (d (x.toNat % 16))) ""

-- RFC 8448 §3 server handshake-traffic secret (provenance-backed).
def secret : ByteArray := hx "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"

def main : IO Unit := do
  let key := KeySchedule.trafficKey .chacha20Poly1305Sha256 secret
  let iv  := KeySchedule.trafficIv secret
  -- A handshake message (EncryptedExtensions) at seq 0, and application data at seq 1.
  let ee  := hx "08 00 00 02 00 00"
  let app := String.toUTF8 "GET / HTTP/1.1\r\nHost: kroopt.test\r\n\r\n"
  let rec0 := Record13.sealRecord key iv 0 ee  .handshake 0
  let rec1 := Record13.sealRecord key iv 1 app .applicationData 0
  IO.println s!"SECRET {toHex secret}"
  IO.println s!"REC handshake 0 {toHex ee} {toHex rec0}"
  IO.println s!"REC applicationData 1 {toHex app} {toHex rec1}"

end Tests.WireDump

def main : IO Unit := Tests.WireDump.main
