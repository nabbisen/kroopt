import Kroopt.Core.Step
import Kroopt.Parse.Handshake
import Kroopt.Parse.Wire
import Kroopt.Crypto.RealProvider
import Kroopt.Crypto.Arena
import Kroopt.Crypto.Hacl
import Kroopt.Conn.Flight
import Kroopt.Conn.Record13
import Kroopt.Crypto.KeySchedule

/-!
# Tests.RealHandshake

Drives the **real** verified core `Kroopt.Core.step` state machine through a server
handshake against the **real** crypto provider (`RealProvider`, real HACL X25519 /
HKDF / Ed25519 / HMAC) with a **real transcript** assembled by `Kroopt.Conn.Flight`.

This is the live loop, server side: a real ClientHello enters as transport bytes,
the core drives the flight, and at the crypto seam the driver substitutes the real
transcript hashes (the core models them as abstract snapshots) and, where the core
commits a structural placeholder to the wire, assembles the real message bytes and
appends them to a real transcript. The handshake runs to `sentServerFinished`
(server flight emitted, application keys installed); the client Finished →
`connected` step, real records, and the socket transport remain future work.

The ClientHello offers `ed25519` in `signature_algorithms` (kroopt's certificate is
Ed25519; the vendored HACL subset has no RSA/P-256), so this is a self-consistent
handshake rather than a replay of RFC 8448 §3 (whose ClientHello offers only
RSA/ECDSA). The key end-to-end claim it checks: the live core, on real crypto over
real wire bytes, produces a **valid Ed25519 CertificateVerify over the real
transcript** and a complete real server flight.
-/

namespace Tests.RealHandshake

open Kroopt Kroopt.Core Kroopt.Crypto Kroopt.Conn Kroopt.Parse

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

-- Real, valid x25519 client public (provenance: RFC 8448 §3 client key share).
def clientShare : ByteArray := hx "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
-- Chosen server values (server ephemeral private from RFC 8448 §3; any random for SH).
def serverPriv   : ByteArray := hx "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
def serverRandom : ByteArray := hx "a6af06a412186024" |>.append (hx "9cd34c95930c8ac5cb1434dac155772ed3e26928")
-- kroopt's Ed25519 certificate key (provenance: RFC 8032 §7.1 Test 1).
def certSeed : ByteArray := hx "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
def certPub  : ByteArray := hx "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
-- Opaque placeholder leaf DER (real certificate provisioning is a separate step).
def placeholderDer : ByteArray := ByteArray.mk (Array.mkArray 48 (0x11 : UInt8))

def cfg : RealCryptoConfig :=
  { ephemeralPrivate := serverPriv, certPrivate := certSeed, certPublic := certPub }

/-- A custom ClientHello (offers x25519 key_share, ed25519 sig_alg, TLS 1.3). -/
def clientHelloMsg : ByteArray :=
  let random : ByteArray := ByteArray.mk (Array.mkArray 32 (0xAB : UInt8))
  let suites : ByteArray := hx "13 01 13 03"
  let supVer : ByteArray := hx "00 2b 00 03 02 03 04"
  let supGrp : ByteArray := hx "00 0a 00 04 00 02 00 1d"
  let sigAlg : ByteArray := hx "00 0d 00 04 00 02 08 07"
  let ks     : ByteArray := Wire.extension 0x0033 (Wire.u16Len (Wire.keyShareEntry 0x001d clientShare))
  let exts   : ByteArray := supVer ++ supGrp ++ sigAlg ++ ks
  let body   : ByteArray :=
    Wire.be16 0x0303 ++ random ++ Wire.u8Len ByteArray.empty
      ++ Wire.u16Len suites ++ Wire.u8Len (ByteArray.mk #[(0x00 : UInt8)])
      ++ Wire.u16Len exts
  Wire.handshake 0x01 body

/-- Wrap a handshake message in a TLS plaintext record (outer type 22). -/
def recordWrap (b : ByteArray) : ByteArray :=
  hx "16 03 01" ++ Wire.be16 b.size.toUInt16 ++ b

/-! ## Real-handshake driver -/

structure RD where
  st : State
  arena : SecretArena
  transcript : ByteArray
  serverShare : ByteArray
  lastSig : ByteArray
  sHsTraffic : ByteArray
  cHsTraffic : ByteArray
  sApTraffic : ByteArray
  hCHSH : ByteArray
  hCHCert : ByteArray
  hCHCertVerify : ByteArray
  hCHSF : ByteArray
  outbound : List ByteArray
  errored : Bool

/-- Substitute the core's abstract transcript snapshots with the real hashes. -/
def substitute (d : RD) : CryptoOp → CryptoOp
  | .hkdfExpandLabel alg secret label ctx len =>
      let ctx' : ByteArray :=
        if label == "c hs traffic" || label == "s hs traffic" then d.hCHSH
        else if label == "c ap traffic" || label == "s ap traffic" || label == "exp master" then d.hCHSF
        else ctx
      .hkdfExpandLabel alg secret label ctx' len
  | .signCertificateVerify scheme _ => .signCertificateVerify scheme (Flight.certVerifyContent d.hCHCert)
  | .verifyFinished alg _ received => .verifyFinished alg d.hCHSF received
  | op => op

/-- Run one crypto op against the real provider, threading the arena and capturing
the server share, the CertificateVerify signature, and the server hs-traffic secret. -/
def runReal (d : RD) (op : CryptoOp) : RD × CryptoResult :=
  let op' := substitute d op
  match RealProvider.submit cfg d.arena ⟨0⟩ op' with
  | .error _ => ({ d with errored := true }, CryptoResult.verifyFailed)
  | .ok (a', r) =>
      let d := { d with arena := a' }
      let d := match r with
        | .ecdheComplete ss _ => { d with serverShare := ss }
        | .signature sig => { d with lastSig := sig }
        | .hkdfSecret h =>
            match op' with
            | .hkdfExpandLabel _ _ "s hs traffic" _ _ =>
                { d with sHsTraffic := (a'.getById h.id).getD ByteArray.empty }
            | .hkdfExpandLabel _ _ "c hs traffic" _ _ =>
                { d with cHsTraffic := (a'.getById h.id).getD ByteArray.empty }
            | .hkdfExpandLabel _ _ "s ap traffic" _ _ =>
                { d with sApTraffic := (a'.getById h.id).getD ByteArray.empty }
            | _ => d
        | _ => d
      (d, r)

/-- On a placeholder `writeTransport`, assemble the real message, append it to the
real transcript, and snapshot the bound transcript hash. -/
def appendReal (d : RD) (placeholder : ByteArray) : RD :=
  if placeholder.size == 0 then d else
  let tag := placeholder.get! 0
  let msg : ByteArray :=
    if tag == 2 then Flight.serverHelloMessage serverRandom d.serverShare 0x1301 0x001d 0x0304
    else if tag == 8 then Wire.encryptedExtensions ByteArray.empty
    else if tag == 11 then Wire.certificate ByteArray.empty (Wire.certificateEntry placeholderDer ByteArray.empty)
    else if tag == 15 then Wire.certificateVerify 0x0807 d.lastSig
    else if tag == 20 then Flight.serverFinishedMessage d.sHsTraffic d.hCHCertVerify
    else placeholder
  let transcript' := d.transcript ++ msg
  let d := { d with transcript := transcript', outbound := d.outbound ++ [msg] }
  if tag == 2 then { d with hCHSH := Hacl.sha256 transcript' }
  else if tag == 11 then { d with hCHCert := Hacl.sha256 transcript' }
  else if tag == 15 then { d with hCHCertVerify := Hacl.sha256 transcript' }
  else if tag == 20 then { d with hCHSF := Hacl.sha256 transcript' }
  else d

def applyAction (d : RD) : OutputAction → RD × List InputEvent
  | .writeTransport _ bytes => (appendReal d bytes, [])
  | .callCrypto c op req =>
      let (d', r) := runReal d req
      (d', [InputEvent.cryptoResult c op r])
  | .reportHandshakeComplete _ _ => (d, [])
  | .failWithAlert _ _ => ({ d with errored := true }, [])
  | .reportError _ _ => ({ d with errored := true }, [])
  | _ => (d, [])

def step1 (d : RD) (ev : InputEvent) : RD × List InputEvent :=
  if d.errored then (d, []) else
  match step d.st ev with
  | .error _ => ({ d with errored := true }, [])
  | .ok (s', acts) =>
      acts.foldl
        (fun (acc : RD × List InputEvent) a =>
          let (d', evs) := applyAction acc.1 a
          (d', acc.2 ++ evs))
        ({ d with st := s' }, [])

def driveFuel : Nat → RD → List InputEvent → RD
  | 0, d, _ => d
  | _, d, [] => d
  | fuel + 1, d, ev :: rest =>
      let (d', newEvs) := step1 d ev
      driveFuel fuel d' (newEvs ++ rest)

def fresh : RD :=
  { st := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
    arena := SecretArena.empty
    transcript := clientHelloMsg
    serverShare := ByteArray.empty, lastSig := ByteArray.empty, sHsTraffic := ByteArray.empty, cHsTraffic := ByteArray.empty, sApTraffic := ByteArray.empty
    hCHSH := ByteArray.empty, hCHCert := ByteArray.empty
    hCHCertVerify := ByteArray.empty, hCHSF := ByteArray.empty
    outbound := [], errored := false }

def run : RD :=
  let d1 := driveFuel 256 fresh [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap clientHelloMsg)]
  if d1.errored then d1 else
  -- Real client Finished = HMAC(finished_key(client hs-traffic), Transcript-Hash(CH‥ServerFinished)).
  let cfVerifyData := Hacl.hmac256 (KeySchedule.finishedKey d1.cHsTraffic) d1.hCHSF
  let clientFinished := Wire.finished cfVerifyData
  driveFuel 64 d1 [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap clientFinished)]

/-- Negative control: a wrong client Finished must be rejected (no `connected`). -/
def runBadFinished : RD :=
  let d1 := driveFuel 256 fresh [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap clientHelloMsg)]
  if d1.errored then d1 else
  let bad := Wire.finished (ByteArray.mk (Array.mkArray 32 (0x55 : UInt8)))
  driveFuel 64 d1 [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap bad)]

def phaseName (p : HandshakeState) : String :=
  match p with
  | .sentServerFinished => "sentServerFinished"
  | .connected => "connected"
  | .failed _ => "failed"
  | _ => "other"

def main : IO UInt32 := do
  let d := run
  let reached := phaseName d.st.handshake
  let reachedConnected := reached == "connected"
  let firstBytes := d.outbound.map (fun (m : ByteArray) => if m.size == 0 then 0xFF else m.get! 0)
  let realSH := Flight.serverHelloMessage serverRandom d.serverShare 0x1301 0x001d 0x0304
  let fin := d.outbound.getD 4 ByteArray.empty

  -- After `connected`, protect a real application-data record with the handshake's
  -- negotiated server application-traffic key/IV (ChaCha20-Poly1305).
  let appKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d.sApTraffic
  let appIv  := KeySchedule.trafficIv d.sApTraffic
  let appPlain := String.toUTF8 "HTTP/1.1 200 OK\r\n\r\nhello over kroopt TLS\n"
  let appRecord := Record13.sealRecord appKey appIv 0 appPlain .applicationData 0
  let appRoundTrip :=
    reachedConnected &&
    (match Record13.openRecord appKey appIv 0 appRecord with
     | some (c, t) => eqB c appPlain && t == ContentType.applicationData
     | none => false)
  let appEncrypted := reachedConnected && !(eqB (appRecord.extract 5 appRecord.size) appPlain)

  let checks : List (String × Bool) :=
    [ ("live step handshake did not error", !d.errored)
    , (s!"reached connected (got {reached})", reachedConnected)
    , ("server ECDHE share captured (32 octets)", d.serverShare.size == 32)
    , ("CH‥SH real transcript hash computed (32 octets)", d.hCHSH.size == 32)
    , ("CH‥Certificate real transcript hash computed (32 octets)", d.hCHCert.size == 32)
    , ("live handshake produced a VALID Ed25519 CertificateVerify over the real transcript",
        Flight.verifyCertVerify certPub d.hCHCert d.lastSig == true)
    , ("CertificateVerify rejects a wrong transcript hash (control)",
        Flight.verifyCertVerify certPub d.hCHSH d.lastSig == false)
    , ("client + server hs-traffic secrets captured (32 octets each)",
        d.cHsTraffic.size == 32 && d.sHsTraffic.size == 32)
    , ("client and server hs-traffic secrets differ", !(eqB d.cHsTraffic d.sHsTraffic))
    , ("server flight is 5 messages", d.outbound.length == 5)
    , ("server flight order is SH, EE, Cert, CertVerify, Finished",
        firstBytes == [2, 8, 11, 15, 20])
    , ("first flight message is the real assembled ServerHello", eqB (d.outbound.getD 0 ByteArray.empty) realSH)
    , ("server Finished framing (type 20, 32-octet verify_data)",
        fin.size == 36 && fin.get! 0 == 0x14 && fin.get! 3 == 0x20)
    , ("a WRONG client Finished is rejected — does not reach connected",
        phaseName runBadFinished.st.handshake != "connected")
    , ("after connected, a real application record round-trips under the negotiated keys", appRoundTrip)
    , ("the application record body is ciphertext, not plaintext", appEncrypted)
    ]

  let mut failed := 0
  IO.println "kroopt live step-driven real handshake to connected (real provider + real transcript + real client Finished):"
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

end Tests.RealHandshake

def main : IO UInt32 := Tests.RealHandshake.main
