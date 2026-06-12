import Kroopt.Conn.Record13
import Kroopt.Crypto.KeySchedule

/-!
# Tests.SocketHandshake

Exchanges a TLS 1.3 server flight as real `Kroopt.Conn.Record13` records over a
**real OS socket** (an AF_UNIX socketpair), confirming the sealed records survive
real kernel I/O and open on the peer. The socket helpers
(`Kroopt/Native/kroopt_socket.c`) are test-only transport-binding glue; kroopt's
production core performs no syscalls and reaches the network only through iotakt
(RFC 010). One fd plays the peer, the other kroopt; the record layer is the real one.
-/

namespace Tests.SocketHandshake

open Kroopt.Conn
open Kroopt.Crypto
open Kroopt.Core (ContentType)

@[extern "kroopt_socketpair"] opaque sockpairRaw : IO UInt64
@[extern "kroopt_sock_write"] opaque sockWrite (fd : UInt32) (buf : ByteArray) : IO UInt64
@[extern "kroopt_sock_read"]  opaque sockRead (fd : UInt32) (n : UInt32) : IO ByteArray
@[extern "kroopt_sock_close"] opaque sockClose (fd : UInt32) : IO Unit

def socketpair : IO (UInt32 × UInt32) := do
  let packed ← sockpairRaw
  pure ((packed >>> 32).toUInt32, (packed &&& 0xFFFFFFFF).toUInt32)

/-- Read exactly one TLS record (5-byte header + length-prefixed body) from `fd`. -/
def readRecord (fd : UInt32) : IO ByteArray := do
  let hdr ← sockRead fd 5
  if hdr.size < 5 then pure hdr
  else
    let len := (hdr.get! 3).toNat * 256 + (hdr.get! 4).toNat
    let body ← sockRead fd len.toUInt32
    pure (hdr ++ body)

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

def be16 (n : Nat) : ByteArray := ByteArray.mk #[((n / 256) % 256).toUInt8, (n % 256).toUInt8]
def zeros (n : Nat) : ByteArray := ByteArray.mk (Array.mkArray n (0 : UInt8))
/-- A plaintext TLS record (used for the cleartext ServerHello). -/
def plainRecord (ctype : UInt8) (body : ByteArray) : ByteArray :=
  (ByteArray.mk #[ctype, 0x03, 0x03]) ++ be16 body.size ++ body

-- RFC 8448 §3 traffic secrets (provenance-backed).
def sHs : ByteArray := hx "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
def cHs : ByteArray := hx "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
def sAp : ByteArray := hx "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"

def keyOf (s : ByteArray) : ByteArray := KeySchedule.trafficKey .chacha20Poly1305Sha256 s
def ivOf  (s : ByteArray) : ByteArray := KeySchedule.trafficIv s

def opensTo (o : Option (ByteArray × ContentType)) (msg : ByteArray) (ct : ContentType) : Bool :=
  match o with
  | some (m, c) => m.toList == msg.toList && (ContentType.toByte c == ContentType.toByte ct)
  | none => false

def main : IO Unit := do
  IO.println "kroopt TLS 1.3 flight over a real OS socket (AF_UNIX socketpair):"
  let (a, b) ← socketpair   -- a = peer side, b = kroopt server side

  -- 0) trivial FFI round-trip
  let probe := String.toUTF8 "kroopt-over-socket"
  let _ ← sockWrite a probe
  let gotProbe ← sockRead b probe.size.toUInt32
  let probeOk := gotProbe.toList == probe.toList

  -- 1) kroopt seals its server flight and writes ServerHello + 4 records to the socket
  let shk := keyOf sHs; let shi := ivOf sHs
  let sh   := hx "02 00 00 04 03 03 00 00"           -- representative ServerHello
  let ee   := hx "08 00 00 02 00 00"                 -- EncryptedExtensions
  let cert := hx "0b 00 00 05 00 00 01 00 00"        -- Certificate (short, for transport)
  let cv   := hx "0f 00 00 06 08 07 00 02 ab cd"     -- CertificateVerify (ed25519 scheme)
  let fin  := (hx "14 00 00 20") ++ zeros 32         -- Finished (32-byte verify_data slot)
  let r0 := Record13.sealRecord shk shi 0 ee   .handshake 0
  let r1 := Record13.sealRecord shk shi 1 cert .handshake 0
  let r2 := Record13.sealRecord shk shi 2 cv   .handshake 0
  let r3 := Record13.sealRecord shk shi 3 fin  .handshake 0
  let _ ← sockWrite b (plainRecord 22 sh)
  let _ ← sockWrite b ((r0 ++ r1 ++ r2) ++ r3)

  -- 2) the peer reads the 5 records back off the socket and opens the encrypted ones
  let recSH ← readRecord a
  let er0 ← readRecord a; let er1 ← readRecord a; let er2 ← readRecord a; let er3 ← readRecord a
  let recsAreCiphertext :=
    er0.get! 0 == 0x17 && er1.get! 0 == 0x17 && er2.get! 0 == 0x17 && er3.get! 0 == 0x17
  let flightOk :=
    recSH.get! 0 == 22 && recSH.get! 5 == 0x02   -- cleartext handshake record carrying ServerHello
    && opensTo (Record13.openRecord shk shi 0 er0) ee   .handshake
    && opensTo (Record13.openRecord shk shi 1 er1) cert .handshake
    && opensTo (Record13.openRecord shk shi 2 er2) cv   .handshake
    && opensTo (Record13.openRecord shk shi 3 er3) fin  .handshake

  -- 3) the peer seals a client Finished and writes it; kroopt reads + opens it
  let chk := keyOf cHs; let chi := ivOf cHs
  let cfin := (hx "14 00 00 20") ++ zeros 32
  let _ ← sockWrite a (Record13.sealRecord chk chi 0 cfin .handshake 0)
  let kGot ← readRecord b
  let finishedOk := kGot.get! 0 == 0x17 && opensTo (Record13.openRecord chk chi 0 kGot) cfin .handshake

  -- 4) application data under the server application-traffic key, over the socket
  let apk := keyOf sAp; let api := ivOf sAp
  let app := String.toUTF8 "hello from kroopt over a real socket"
  let _ ← sockWrite b (Record13.sealRecord apk api 0 app .applicationData 0)
  let peerApp ← readRecord a
  let appOk := opensTo (Record13.openRecord apk api 0 peerApp) app .applicationData

  sockClose a; sockClose b

  let checks : List (String × Bool) :=
    [ ("a real socketpair round-trips bytes through the kernel", probeOk)
    , ("the server flight reads back off the socket as TLSCiphertext records", recsAreCiphertext)
    , ("the peer opens kroopt's flight (ServerHello + EE/Cert/CertVerify/Finished) over the socket", flightOk)
    , ("kroopt reads and opens the peer's encrypted Finished record off the socket", finishedOk)
    , ("application data round-trips encrypted over the socket", appOk) ]
  let mut passed := 0
  for (name, ok) in checks do
    IO.println s!"  {if ok then "PASS" else "FAIL"}  {name}"
    if ok then passed := passed + 1
  if passed == checks.length then IO.println s!"All {passed} checks passed."
  else IO.eprintln "FAILED"

end Tests.SocketHandshake

def main : IO Unit := Tests.SocketHandshake.main
