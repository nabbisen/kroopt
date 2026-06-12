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
-- A real, OpenSSL-parseable self-signed Ed25519 X.509 certificate whose subject
-- public key is kroopt's certificate key (CN=kroopt.test, 100-year validity).
-- Generated from the cert seed by `scripts/gen-test-cert.sh`.
def certDer : ByteArray := hx
  "3082015b3082010da003020102021409cf89b7545d532c3c9b338845e68dd9f2dd9208300506032b657030163114301206035504030c0b6b726f6f70742e746573743020170d3236303631323034323730335a180f32313236303531393034323730335a30163114301206035504030c0b6b726f6f70742e74657374302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511aa36b3069301d0603551d0e041604145b27aa5589179770e47575b162a1ded97b8bfc6d301f0603551d230418301680145b27aa5589179770e47575b162a1ded97b8bfc6d300f0603551d130101ff040530030101ff30160603551d11040f300d820b6b726f6f70742e74657374300506032b6570034100afb247f952fd77d308bb94d2b703b5ad82882f4a6a40dd2a4974c97cea7239de64fb60ad6bfc42d0a48101eea1bb921a1d7aa18081e6a1945935d60384501903"

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
  writeSeq : Nat
  sealedFlight : List (Nat × ByteArray × ByteArray)
  cfWireSealed : ByteArray
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
    if tag == 2 then Flight.serverHelloMessage serverRandom d.serverShare 0x1303 0x001d 0x0304
    else if tag == 8 then Wire.encryptedExtensions ByteArray.empty
    else if tag == 11 then Wire.certificate ByteArray.empty (Wire.certificateEntry certDer ByteArray.empty)
    else if tag == 15 then Wire.certificateVerify 0x0807 d.lastSig
    else if tag == 20 then Flight.serverFinishedMessage d.sHsTraffic d.hCHCertVerify
    else placeholder
  let transcript' := d.transcript ++ msg
  -- Wire record protection (interpreter): ServerHello goes in the clear; the rest of
  -- the flight is sealed as real TLSCiphertext records under the server
  -- handshake-traffic key, one record per message with an increasing sequence.
  let d :=
    if tag == 8 || tag == 11 || tag == 15 || tag == 20 then
      let hsKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d.sHsTraffic
      let hsIv  := KeySchedule.trafficIv d.sHsTraffic
      let sealed := Record13.sealRecord hsKey hsIv d.writeSeq.toUInt64 msg .handshake 0
      { d with sealedFlight := d.sealedFlight ++ [(d.writeSeq, msg, sealed)], writeSeq := d.writeSeq + 1 }
    else d
  let d := { d with transcript := transcript', outbound := d.outbound ++ [msg] }
  if tag == 2 then { d with hCHSH := Hacl.sha256 transcript' }
  else if tag == 11 then { d with hCHCert := Hacl.sha256 transcript' }
  else if tag == 15 then { d with hCHCertVerify := Hacl.sha256 transcript' }
  else if tag == 20 then { d with hCHSF := Hacl.sha256 transcript' }
  else d

/-- Realize a typed `writeHandshake` message (RFC 032) the same way `appendReal` realizes
the EncryptedExtensions placeholder: serialize via the shared core serializer, seal it as
a handshake-epoch record, and commit it to the real transcript and outbound. No first-byte
dispatch. (Slice 1: EncryptedExtensions, which carries no bound transcript hash.) -/
def appendRealHandshakeOut (d : RD) (m : Kroopt.Core.HandshakeOut) : RD :=
  let msg := Kroopt.Core.serializeHandshakeOut m
  let transcript' := d.transcript ++ msg
  let hsKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d.sHsTraffic
  let hsIv  := KeySchedule.trafficIv d.sHsTraffic
  let sealed := Record13.sealRecord hsKey hsIv d.writeSeq.toUInt64 msg .handshake 0
  let d := { d with sealedFlight := d.sealedFlight ++ [(d.writeSeq, msg, sealed)], writeSeq := d.writeSeq + 1,
                    transcript := transcript', outbound := d.outbound ++ [msg] }
  -- CertificateVerify binds the transcript hash the server Finished MAC is taken over.
  match m with
  | .certificateVerify _ _ => { d with hCHCertVerify := Hacl.sha256 transcript' }
  | _ => d

/-- Realize a typed `writeCertificate` action (RFC 032): the interpreter resolves the
chain handle to DER. The test driver's configured chain is `certDer`; it serializes the
real Certificate, seals it as a handshake-epoch record, commits it to the transcript, and
binds the CH‥Certificate hash the CertificateVerify signature is taken over. -/
def appendRealCert (d : RD) : RD :=
  let msg := Wire.certificate ByteArray.empty (Wire.certificateEntry certDer ByteArray.empty)
  let transcript' := d.transcript ++ msg
  let hsKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d.sHsTraffic
  let hsIv  := KeySchedule.trafficIv d.sHsTraffic
  let sealed := Record13.sealRecord hsKey hsIv d.writeSeq.toUInt64 msg .handshake 0
  { d with sealedFlight := d.sealedFlight ++ [(d.writeSeq, msg, sealed)], writeSeq := d.writeSeq + 1,
           transcript := transcript', outbound := d.outbound ++ [msg],
           hCHCert := Hacl.sha256 transcript' }

def applyAction (d : RD) : OutputAction → RD × List InputEvent
  | .writeTransport _ bytes => (appendReal d bytes, [])
  | .writeHandshake _ msg => (appendRealHandshakeOut d msg, [])
  | .writeCertificate _ _ => (appendRealCert d, [])
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
    writeSeq := 0, sealedFlight := [], cfWireSealed := ByteArray.empty
    hCHSH := ByteArray.empty, hCHCert := ByteArray.empty
    hCHCertVerify := ByteArray.empty, hCHSF := ByteArray.empty
    outbound := [], errored := false }

def run : RD :=
  let d1 := driveFuel 256 fresh [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap clientHelloMsg)]
  if d1.errored then d1 else
  -- Real client Finished = HMAC(finished_key(client hs-traffic), Transcript-Hash(CH‥ServerFinished)).
  let cfVerifyData := Hacl.hmac256 (KeySchedule.finishedKey d1.cHsTraffic) d1.hCHSF
  let clientFinished := Wire.finished cfVerifyData
  -- The client sends its Finished as an encrypted handshake record; the interpreter
  -- opens it with the client handshake-traffic key and feeds the plaintext to the core.
  let cKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d1.cHsTraffic
  let cIv  := KeySchedule.trafficIv d1.cHsTraffic
  let cfSealed := Record13.sealRecord cKey cIv 0 clientFinished .handshake 0
  let cfPlain := match Record13.openRecord cKey cIv 0 cfSealed with | some (c, _) => c | none => ByteArray.empty
  driveFuel 64 { d1 with cfWireSealed := cfSealed } [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap cfPlain)]

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

/-- **RFC 033 increment — the client Finished opens *in the core*.** Drive the
real, sealed client-Finished record (outer `application_data`, the actual wire
form) through `step`. The core must (1) open it under the **handshake** epoch
rather than silently drop it, (2) route the opened inner Finished through the
handshake model to a `verifyFinished` request, and (3) reach `connected` on a
successful verify — all without ever buffering application plaintext. The opened
inner bytes are supplied as the `aeadOpened` crypto result (the interpreter's job;
real decryption is covered by the record/interop suites), so this exercises the
core half of the contract that this increment changed. Returns
`(opensUnderHandshake, routedToVerify, reachedConnected, noPlaintextLeak)`. -/
def protectedFinishedDrive : Bool × Bool × Bool × Bool :=
  let d1 := driveFuel 256 fresh [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap clientHelloMsg)]
  if d1.errored then (false, false, false, false) else
  let cfVerifyData := Hacl.hmac256 (KeySchedule.finishedKey d1.cHsTraffic) d1.hCHSF
  let clientFinished := Wire.finished cfVerifyData
  let cKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d1.cHsTraffic
  let cIv  := KeySchedule.trafficIv d1.cHsTraffic
  let cfSealed := Record13.sealRecord cKey cIv 0 clientFinished .handshake 0
  match step d1.st (InputEvent.transportBytes ⟨0, 0⟩ cfSealed) with
  | .error _ => (false, false, false, false)
  | .ok (s1, acts1) =>
      match acts1.findSome? (fun a => match a with
              | OutputAction.callCrypto _ oid (CryptoOp.aeadOpen meta _ _) => some (oid, meta.epoch)
              | _ => none) with
      | none => (false, false, false, false)
      | some (oid, ep) =>
          let opensUnderHandshake := match ep with | .handshake => true | _ => false
          let innerPt := clientFinished ++ ByteArray.mk #[22]   -- inner content-type = handshake
          match step s1 (InputEvent.cryptoResult ⟨0, 0⟩ oid (CryptoResult.aeadOpened innerPt)) with
          | .error _ => (opensUnderHandshake, false, false, false)
          | .ok (s2, acts2) =>
              let noPlaintextLeak := match s2.pendingPlainOut with | none => true | _ => false
              match acts2.findSome? (fun a => match a with
                      | OutputAction.callCrypto _ o (CryptoOp.verifyFinished _ _ _) => some o
                      | _ => none) with
              | none => (opensUnderHandshake, false, false, noPlaintextLeak)
              | some o2 =>
                  let routedToVerify := match s2.handshake with
                    | .requestedClientFinishedVerify => true | _ => false
                  match step s2 (InputEvent.cryptoResult ⟨0, 0⟩ o2 CryptoResult.verified) with
                  | .error _ => (opensUnderHandshake, routedToVerify, false, noPlaintextLeak)
                  | .ok (s3, _) =>
                      let reachedConnected := match s3.handshake with | .connected => true | _ => false
                      (opensUnderHandshake, routedToVerify, reachedConnected, noPlaintextLeak)

/-- **RFC 033 reassembler — unit.** `frameHandshakeMessage` frames exactly one complete
handshake message (header included), reports `none` while incomplete, and returns the
tail when a record coalesces a message with trailing bytes. -/
def reasmFramingOk : Bool :=
  let complete  := ByteArray.mk #[1, 0, 0, 3, 0xAA, 0xBB, 0xCC]   -- type 1, len 3, 3 body
  let incomplete := ByteArray.mk #[1, 0, 0, 3, 0xAA]              -- only 1 of 3 body bytes
  let coalesced := ByteArray.mk #[1, 0, 0, 1, 0x42, 0x99]        -- a 1-byte msg + 1 trailing
  (match frameHandshakeMessage complete with
   | some (m, r) => m.size == 7 && r.size == 0 | none => false)
  && (frameHandshakeMessage incomplete).isNone
  && (match frameHandshakeMessage coalesced with
      | some (m, r) => m.size == 5 && r.size == 1 | none => false)

/-- **RFC 033 reassembler — fragmentation.** A ClientHello split across two handshake
records is reassembled and drives to the *same* state as the same ClientHello delivered
in one record (`run`). -/
def fragmentedClientHelloReachesSameState : Bool :=
  let ch := clientHelloMsg
  let half := ch.size / 2
  let whole := driveFuel 256 fresh [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap ch)]
  let frag := driveFuel 256 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ (recordWrap (ch.extract 0 half)),
     InputEvent.transportBytes ⟨0, 0⟩ (recordWrap (ch.extract half ch.size))]
  !frag.errored && !whole.errored
    && frag.st.handshake == whole.st.handshake
    && frag.st.handshake == .sentServerFinished

/-- A handshake message whose header claims a huge length never completes; fed across
enough records to pass `maxHandshakeReasmBytes`, it fails the connection rather than
buffering without bound. -/
def bigHdrFrag : ByteArray :=
  (ByteArray.mk #[1, 0xFF, 0xFF, 0xFF]) ++ ByteArray.mk (Array.mkArray 16000 (0x00 : UInt8))
def oversizedReasmFails : Bool :=
  let ev := InputEvent.transportBytes ⟨0, 0⟩ (recordWrap bigHdrFrag)
  (driveFuel 64 fresh [ev, ev, ev, ev, ev]).errored

def main : IO UInt32 := do
  let d := run
  let reached := phaseName d.st.handshake
  let reachedConnected := reached == "connected"
  let firstBytes := d.outbound.map (fun (m : ByteArray) => if m.size == 0 then 0xFF else m.get! 0)
  let realSH := Flight.serverHelloMessage serverRandom d.serverShare 0x1303 0x001d 0x0304
  let fin := d.outbound.getD 4 ByteArray.empty

  -- Wire record protection: the encrypted flight (EE/Cert/CertVerify/Finished) was
  -- sealed as real TLSCiphertext records under the server handshake-traffic key.
  let hsKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d.sHsTraffic
  let hsIv  := KeySchedule.trafficIv d.sHsTraffic
  let flightCount := d.sealedFlight.length == 4
  let flightSeqs := (d.sealedFlight.map (fun (t : Nat × ByteArray × ByteArray) => t.1)) == [0, 1, 2, 3]
  let flightIsCiphertext := d.sealedFlight.all (fun (t : Nat × ByteArray × ByteArray) =>
    let sealed := t.2.2; sealed.size > 5 && sealed.get! 0 == 0x17 && !(eqB sealed t.2.1))
  let flightOpensBack := d.sealedFlight.all (fun (t : Nat × ByteArray × ByteArray) =>
    match Record13.openRecord hsKey hsIv t.1.toUInt64 t.2.2 with
    | some (c, ct) => eqB c t.2.1 && ct == ContentType.handshake
    | none => false)

  -- Inbound: the client's encrypted Finished record opens to the plaintext Finished.
  let cKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 d.cHsTraffic
  let cIv  := KeySchedule.trafficIv d.cHsTraffic
  let inboundIsCiphertext := d.cfWireSealed.size > 5 && d.cfWireSealed.get! 0 == 0x17
  let inboundOpensBack := match Record13.openRecord cKey cIv 0 d.cfWireSealed with
    | some (c, ct) => ct == ContentType.handshake && c.size == 36 && c.get! 0 == 0x14
    | none => false

  -- The Certificate message presents the real X.509 certificate.
  let certMsg := d.outbound.getD 2 ByteArray.empty
  let realCertPresented :=
    certDer.size == 351 && certDer.get! 0 == 0x30 && certDer.get! 1 == 0x82
    && certMsg.get! 0 == 0x0b
    && eqB (certMsg.extract 11 (11 + certDer.size)) certDer

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
    , ("the encrypted flight (EE/Cert/CertVerify/Finished) is sealed as 4 TLSCiphertext records", flightCount && flightIsCiphertext)
    , ("the sealed flight records carry handshake-epoch sequences 0,1,2,3", flightSeqs)
    , ("each sealed flight record opens back to its plaintext handshake message", flightOpensBack)
    , ("the client's encrypted Finished record is ciphertext and opens to the plaintext Finished", inboundIsCiphertext && inboundOpensBack)
    , ("the Certificate message presents a real OpenSSL-parseable Ed25519 X.509 cert", realCertPresented)
    , ("the SEALED client Finished opens IN THE CORE under the handshake epoch (RFC 033)",
        protectedFinishedDrive.1)
    , ("the opened inner Finished is routed to verifyFinished (not dropped)",
        protectedFinishedDrive.2.1)
    , ("the in-core protected-record path reaches connected",
        protectedFinishedDrive.2.2.1)
    , ("opening the protected handshake record buffers no application plaintext",
        protectedFinishedDrive.2.2.2)
    , ("frameHandshakeMessage frames one message, reports incomplete, splits coalesced (RFC 033)",
        reasmFramingOk)
    , ("a ClientHello split across two records reassembles to the same state as one record (RFC 033)",
        fragmentedClientHelloReachesSameState)
    , ("an over-large handshake reassembly buffer fails the connection (RFC 033)",
        oversizedReasmFails)
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
