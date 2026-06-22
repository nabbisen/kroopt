import Kroopt.Core.Step
import Kroopt.Parse.Wire
import Kroopt.Parse.Handshake

/-!
# Tests.EndToEnd

The full synthetic handshake driven **through `Kroopt.Core.step`** against a fake
transport and a deterministic fake crypto provider (RFC 014 §3–§6). No sockets,
no real crypto: `callCrypto` actions are answered by `fakeCrypto` and fed back as
`cryptoResult` events; `writeTransport` actions are logged; `emitPlaintext` is
logged so negative tests can assert it never fires before `connected`.

This is the v0.1 acceptance demonstration (RFC 014 §10): a real ClientHello byte
sequence enters as `transportBytes`, the record/handshake handlers parse and
drive the flight, and the connection reaches `connected` with a
`reportHandshakeComplete`.
-/

namespace Tests.EndToEnd

open Kroopt Kroopt.Core

structure Check where
  name : String
  ok : Bool

def b (l : List UInt8) : ByteArray := ByteArray.mk l.toArray

/-! ## A valid ClientHello, record-framed -/

def keyShareEntry : List UInt8 := [0x00, 0x1d, 0, 32] ++ List.replicate 32 0x07  -- 32-byte x25519 share (RFC 8446 §4.2.8.2)
def extKeyShare : List UInt8 := [0, 51, 0, 38, 0, 36] ++ keyShareEntry
def extSigAlgs : List UInt8 := [0, 0x0d, 0, 4, 0, 2, 0x08, 0x07]  -- signature_algorithms: ed25519
def extSupVer : List UInt8 := [0, 43, 0, 3, 2, 0x03, 0x04]
def extsBody : List UInt8 := extSupVer ++ extKeyShare ++ extSigAlgs

def u16be (n : Nat) : List UInt8 := [(n / 256).toUInt8, (n % 256).toUInt8]

def chBody : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBody.length ++ extsBody)

def chMsg : List UInt8 :=
  [1] ++ [0, (chBody.length / 256).toUInt8, (chBody.length % 256).toUInt8] ++ chBody

/-- Wrap a handshake message in a TLSPlaintext record (outer type 22). -/
def record (body : List UInt8) : ByteArray :=
  b ([22, 0x03, 0x03] ++ u16be body.length ++ body)

def chRecord : ByteArray := record chMsg
def clientFinishedRecord : ByteArray := record ([20] ++ [0, 0, 32] ++ List.replicate 32 0x55)

/-! ## A secp256r1-only ClientHello (RFC 8446 §4.2.8.2: group 0x0017, 65-byte
uncompressed point `0x04 ‖ X ‖ Y`). Identical to `chRecord` except the sole
key_share is P-256 — exercising the secp256r1 negotiation path end-to-end. -/

def keyShareEntryP256 : List UInt8 := [0x00, 0x17, 0, 65] ++ ([0x04] ++ List.replicate 64 0x07)
def extKeyShareP256 : List UInt8 := [0, 51, 0, 71, 0, 69] ++ keyShareEntryP256
def extsBodyP256 : List UInt8 := extSupVer ++ extKeyShareP256 ++ extSigAlgs
def chBodyP256 : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyP256.length ++ extsBodyP256)
def chMsgP256 : List UInt8 :=
  [1] ++ [0, (chBodyP256.length / 256).toUInt8, (chBodyP256.length % 256).toUInt8] ++ chBodyP256
def chRecordP256 : ByteArray := record chMsgP256

/-! ## A ClientHello offering BOTH x25519 and secp256r1 key_shares (x25519 listed
first), and one with a DUPLICATE x25519 entry (RFC 8446 §4.2.8.2 forbids it). These
exercise RFC 039: server preference picks x25519 over the client's order, and a
duplicate group id is a malformed ClientHello. -/

def keyShareEntryBoth : List UInt8 := keyShareEntry ++ keyShareEntryP256
def extKeyShareBoth : List UInt8 :=
  [0, 51] ++ u16be (keyShareEntryBoth.length + 2) ++ u16be keyShareEntryBoth.length ++ keyShareEntryBoth
def extsBodyBoth : List UInt8 := extSupVer ++ extKeyShareBoth ++ extSigAlgs
def chBodyBoth : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyBoth.length ++ extsBodyBoth)
def chMsgBoth : List UInt8 :=
  [1] ++ [0, (chBodyBoth.length / 256).toUInt8, (chBodyBoth.length % 256).toUInt8] ++ chBodyBoth
def chRecordBoth : ByteArray := record chMsgBoth

def keyShareEntryDup : List UInt8 := keyShareEntry ++ keyShareEntry
def extKeyShareDup : List UInt8 :=
  [0, 51] ++ u16be (keyShareEntryDup.length + 2) ++ u16be keyShareEntryDup.length ++ keyShareEntryDup
def extsBodyDup : List UInt8 := extSupVer ++ extKeyShareDup ++ extSigAlgs
def chBodyDup : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyDup.length ++ extsBodyDup)
def chMsgDup : List UInt8 :=
  [1] ++ [0, (chBodyDup.length / 256).toUInt8, (chBodyDup.length % 256).toUInt8] ++ chBodyDup
def chRecordDup : ByteArray := record chMsgDup

/-! ## An unknown-group + secp256r1 ClientHello (RFC 039 §8.9: unrecognized groups are
dropped, the recognized P-256 share remains), and a DUPLICATE secp256r1 ClientHello. -/

def keyShareEntryUnknown : List UInt8 := [0x01, 0x00, 0, 4] ++ [1, 2, 3, 4]  -- group 0x0100, 4-byte share
def keyShareEntryUnkP256 : List UInt8 := keyShareEntryUnknown ++ keyShareEntryP256
def extKeyShareUnkP256 : List UInt8 :=
  [0, 51] ++ u16be (keyShareEntryUnkP256.length + 2) ++ u16be keyShareEntryUnkP256.length ++ keyShareEntryUnkP256
def extsBodyUnkP256 : List UInt8 := extSupVer ++ extKeyShareUnkP256 ++ extSigAlgs
def chBodyUnkP256 : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyUnkP256.length ++ extsBodyUnkP256)
def chMsgUnkP256 : List UInt8 :=
  [1] ++ [0, (chBodyUnkP256.length / 256).toUInt8, (chBodyUnkP256.length % 256).toUInt8] ++ chBodyUnkP256
def chRecordUnkP256 : ByteArray := record chMsgUnkP256

def keyShareEntryDupP256 : List UInt8 := keyShareEntryP256 ++ keyShareEntryP256
def extKeyShareDupP256 : List UInt8 :=
  [0, 51] ++ u16be (keyShareEntryDupP256.length + 2) ++ u16be keyShareEntryDupP256.length ++ keyShareEntryDupP256
def extsBodyDupP256 : List UInt8 := extSupVer ++ extKeyShareDupP256 ++ extSigAlgs
def chBodyDupP256 : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyDupP256.length ++ extsBodyDupP256)
def chMsgDupP256 : List UInt8 :=
  [1] ++ [0, (chBodyDupP256.length / 256).toUInt8, (chBodyDupP256.length % 256).toUInt8] ++ chBodyDupP256
def chRecordDupP256 : ByteArray := record chMsgDupP256

/-! ## supported_groups / key_share consistency (RFC 039 §4.6). `supported_groups` (ext
0x000a) data is a u16-length-prefixed list of u16 group ids. One ClientHello offers an
x25519 key_share but a `supported_groups` that omits x25519 (a contradiction → reject); the
other lists a group in `supported_groups` but sends no key_share at all (no usable share, no
HRR → clean fail). -/

def extSupGroupsP256Only : List UInt8 := [0, 0x0a, 0, 4, 0, 2, 0x00, 0x17]  -- supported_groups = [secp256r1]
def extSupGroupsX25519 : List UInt8 := [0, 0x0a, 0, 4, 0, 2, 0x00, 0x1d]    -- supported_groups = [x25519]

def extsBodyKsNotInSg : List UInt8 := extSupVer ++ extSupGroupsP256Only ++ extKeyShare ++ extSigAlgs
def chBodyKsNotInSg : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyKsNotInSg.length ++ extsBodyKsNotInSg)
def chMsgKsNotInSg : List UInt8 :=
  [1] ++ [0, (chBodyKsNotInSg.length / 256).toUInt8, (chBodyKsNotInSg.length % 256).toUInt8] ++ chBodyKsNotInSg
def chRecordKsNotInSg : ByteArray := record chMsgKsNotInSg

def extsBodySgNoKs : List UInt8 := extSupVer ++ extSupGroupsX25519 ++ extSigAlgs
def chBodySgNoKs : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodySgNoKs.length ++ extsBodySgNoKs)
def chMsgSgNoKs : List UInt8 :=
  [1] ++ [0, (chBodySgNoKs.length / 256).toUInt8, (chBodySgNoKs.length % 256).toUInt8] ++ chBodySgNoKs
def chRecordSgNoKs : ByteArray := record chMsgSgNoKs

/-! ## Malformed secp256r1 key_share shapes (RFC 039 §4.7/§8.12): a 65-byte point with the
wrong leading byte (not `0x04`), and a 64-byte point (wrong length). The parser surfaces
neither as a P-256 offer, so — being the only offered group — the ClientHello has no usable
key_share and is rejected (illegal_parameter). -/

def keyShareEntryP256BadPrefix : List UInt8 := [0x00, 0x17, 0, 65] ++ ([0x05] ++ List.replicate 64 0x07)
def extKeyShareP256BadPrefix : List UInt8 :=
  [0, 51] ++ u16be (keyShareEntryP256BadPrefix.length + 2) ++ u16be keyShareEntryP256BadPrefix.length ++ keyShareEntryP256BadPrefix
def extsBodyP256BadPrefix : List UInt8 := extSupVer ++ extKeyShareP256BadPrefix ++ extSigAlgs
def chBodyP256BadPrefix : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyP256BadPrefix.length ++ extsBodyP256BadPrefix)
def chMsgP256BadPrefix : List UInt8 :=
  [1] ++ [0, (chBodyP256BadPrefix.length / 256).toUInt8, (chBodyP256BadPrefix.length % 256).toUInt8] ++ chBodyP256BadPrefix
def chRecordP256BadPrefix : ByteArray := record chMsgP256BadPrefix

def keyShareEntryP256BadLen : List UInt8 := [0x00, 0x17, 0, 64] ++ List.replicate 64 0x07
def extKeyShareP256BadLen : List UInt8 :=
  [0, 51] ++ u16be (keyShareEntryP256BadLen.length + 2) ++ u16be keyShareEntryP256BadLen.length ++ keyShareEntryP256BadLen
def extsBodyP256BadLen : List UInt8 := extSupVer ++ extKeyShareP256BadLen ++ extSigAlgs
def chBodyP256BadLen : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBodyP256BadLen.length ++ extsBodyP256BadLen)
def chMsgP256BadLen : List UInt8 :=
  [1] ++ [0, (chBodyP256BadLen.length / 256).toUInt8, (chBodyP256BadLen.length % 256).toUInt8] ++ chBodyP256BadLen
def chRecordP256BadLen : ByteArray := record chMsgP256BadLen

/-! ## Fake crypto provider (deterministic, purpose-aware) -/

def fakeCrypto : CryptoOp → CryptoResult
  | .ecdheX25519 _ => .ecdheComplete (ByteArray.mk (Array.mkArray 32 0)) ⟨1, 0⟩
  | .ecdheP256 _ => .ecdheComplete (ByteArray.mk (Array.mkArray 65 0)) ⟨1, 0⟩
  | .signCertificateVerify _ _ => .signature (b (List.replicate 64 0xCD))
  | .verifyFinished _ _ _ => .verified
  | .aeadSeal _ _ pt => .aeadSealed pt
  | .aeadOpen _ _ ct => .aeadOpened ct
  | .randomBytes _ => .randomBytes (b [])
  | .computeServerFinished _ _ => .finishedMac (b (List.replicate 32 0xEF))
  | .hkdfExtract _ _ _ => .hkdfSecret ⟨2, 0⟩
  | .hkdfExpandLabel _ _ _ _ _ => .hkdfSecret ⟨3, 0⟩
  | .installTrafficKeys _ _ _ _ => .keysInstalled

/-! ## Driver loop -/

structure Driver where
  st : State
  outbound : List ByteArray
  emitted : List ByteArray
  completed : Bool
  errored : Bool
  alerts : List AlertDescription := []

def applyAction (d : Driver) : OutputAction → Driver × List InputEvent
  | .writeTransport _ bytes => ({ d with outbound := d.outbound ++ [bytes] }, [])
  | .writeHandshake _ _ _ msg => ({ d with outbound := d.outbound ++ [Kroopt.Core.serializeHandshakeOut msg] }, [])
  | .writeCertificate _ _ _ _ => ({ d with outbound := d.outbound ++ [Kroopt.Parse.Wire.certificate (ByteArray.mk #[]) (ByteArray.mk #[])] }, [])
  | .callCrypto c op req => (d, [InputEvent.cryptoResult c op (fakeCrypto req)])
  | .reportHandshakeComplete _ _ => ({ d with completed := true }, [])
  | .emitPlaintext _ bytes => ({ d with emitted := d.emitted ++ [bytes] }, [])
  | .reportError _ _ => ({ d with errored := true }, [])
  | .failWithAlert _ a => ({ d with errored := true, alerts := d.alerts ++ [a] }, [])
  | _ => (d, [])

def step1 (d : Driver) (ev : InputEvent) : Driver × List InputEvent :=
  match step d.st ev with
  | .error _ => ({ d with errored := true }, [])
  | .ok (s', acts) =>
      acts.foldl
        (fun (acc : Driver × List InputEvent) a =>
          let (d', evs) := applyAction acc.1 a
          (d', acc.2 ++ evs))
        ({ d with st := s' }, [])

def driveFuel : Nat → Driver → List InputEvent → Driver
  | 0, d, _ => d
  | _, d, [] => d
  | fuel + 1, d, ev :: rest =>
      let (d', newEvs) := step1 d ev
      driveFuel fuel d' (newEvs ++ rest)

def fresh : Driver :=
  { st := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
    outbound := [], emitted := [], completed := false, errored := false }

/-- Run the full handshake: feed the ClientHello record, then (after the server
flight) the client Finished record; crypto results cascade automatically. -/
def runE2E : Driver :=
  driveFuel 256 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ chRecord,
     InputEvent.transportBytes ⟨0, 0⟩ clientFinishedRecord]

/-- The same full handshake driven by a secp256r1-only ClientHello: the core must
select P-256, emit `ecdheP256`, and reach `connected`. -/
def runE2EP256 : Driver :=
  driveFuel 256 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ chRecordP256,
     InputEvent.transportBytes ⟨0, 0⟩ clientFinishedRecord]

/-- A both-groups-offered ClientHello against the default endpoint (allows both): the
server preference (x25519 first) must win over the client's listing order, so x25519 is
negotiated and the handshake completes (RFC 039 §4.3). -/
def runE2EBoth : Driver :=
  driveFuel 256 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ chRecordBoth,
     InputEvent.transportBytes ⟨0, 0⟩ clientFinishedRecord]

/-- A duplicate-group ClientHello: the parser rejects it as malformed (RFC 8446 §4.2.8 /
RFC 039 §4.5), so it never reaches `connected`. -/
def runDupKeyShare : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ chRecordDup]

/-- A hardened endpoint that allows only x25519 (`namedGroups := [.x25519]`). This is the
profile RFC 039 makes *enforceable*: before Stage 4 it was validated at startup but ignored
on selection. -/
def x25519OnlyConfig : ValidatedServerConfig :=
  { ValidatedServerConfig.baseline with
    defaultEndpoint := ValidatedServerConfig.baseline.defaultEndpoint.map
      (fun e => { e with namedGroups := [.x25519] }) }

def freshX25519Only : Driver :=
  { st := { State.initial ⟨0, 0⟩ ⟨0⟩ .sha256 with serverConfig := x25519OnlyConfig }
    outbound := [], emitted := [], completed := false, errored := false }

/-- The live-gap closure: a secp256r1-*only* client meets an x25519-only endpoint. The core
finds no group both allowed and offered and fails with `handshake_failure` (RFC 039 §4.3/§4.8)
— it must NOT negotiate P-256. -/
def runP256ClientX25519OnlyServer : Driver :=
  driveFuel 64 freshX25519Only [InputEvent.transportBytes ⟨0, 0⟩ chRecordP256]

/-- Unknown group dropped, recognized secp256r1 share kept and selected against a both-allowed
endpoint (RFC 039 §8.9). -/
def runUnkP256 : Driver :=
  driveFuel 256 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ chRecordUnkP256,
     InputEvent.transportBytes ⟨0, 0⟩ clientFinishedRecord]

/-- Duplicate secp256r1 key_share → malformed, never connected (RFC 039 §8.10). -/
def runDupP256 : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ chRecordDupP256]

/-- key_share for a group omitted from `supported_groups` → contradiction, rejected (§4.6). -/
def runKsNotInSg : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ chRecordKsNotInSg]

/-- `supported_groups` present but no usable key_share → clean no-HRR failure (§4.6). -/
def runSgNoKs : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ chRecordSgNoKs]

/-- secp256r1 key_share with a non-`0x04` leading byte → not a P-256 offer → rejected (§8.12). -/
def runP256BadPrefix : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ chRecordP256BadPrefix]

/-- secp256r1 key_share of the wrong length (64, not 65) → not a P-256 offer → rejected (§8.12). -/
def runP256BadLen : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ chRecordP256BadLen]

/-! ## Negative scenarios -/

def malformedChRecord : ByteArray := record [1, 0, 0, 4, 0x03, 0x03, 0, 0]  -- complete header (len24=4), body too short for a CH
def runMalformedCH : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ malformedChRecord]

-- application_data record (outer type 23) before connected
def appDataRecord : ByteArray := b ([23, 0x03, 0x03] ++ u16be 4 ++ [9, 9, 9, 9])
def runAppDataEarly : Driver :=
  driveFuel 16 fresh [InputEvent.transportBytes ⟨0, 0⟩ appDataRecord]

-- a bad client Finished: verify fails (provider scripted to verifyFailed)
def fakeCryptoBadFinished : CryptoOp → CryptoResult
  | .verifyFinished _ _ _ => .verifyFailed
  | op => fakeCrypto op

def step1Bad (d : Driver) (ev : InputEvent) : Driver × List InputEvent :=
  match step d.st ev with
  | .error _ => ({ d with errored := true }, [])
  | .ok (s', acts) =>
      acts.foldl
        (fun (acc : Driver × List InputEvent) a =>
          let (d', evs) := match a with
            | .callCrypto c op req => (acc.1, [InputEvent.cryptoResult c op (fakeCryptoBadFinished req)])
            | other => applyAction acc.1 other
          (d', acc.2 ++ evs))
        ({ d with st := s' }, [])

def driveFuelBad : Nat → Driver → List InputEvent → Driver
  | 0, d, _ => d
  | _, d, [] => d
  | fuel + 1, d, ev :: rest =>
      let (d', newEvs) := step1Bad d ev
      driveFuelBad fuel d' (newEvs ++ rest)

def runBadFinished : Driver :=
  driveFuelBad 64 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ chRecord,
     InputEvent.transportBytes ⟨0, 0⟩ clientFinishedRecord]

/-- Did the driver emit `a` as a fatal alert? (`AlertDescription` has `DecidableEq`, not
`BEq`, so compare via `decide`.) -/
def hasAlert (d : Driver) (a : AlertDescription) : Bool := d.alerts.any (fun x => decide (x = a))

/-! ## Negotiation-trace redaction (RFC 039 §4.9). The offered share carries a recognizable
0xBE (=190) fill; the rendered trace must surface group ids (x25519=29, secp256r1=23) and the
selected group, but never that share byte. -/
def sampleTraceShares : List (NamedGroup × ByteArray) :=
  [(.secp256r1, (ByteArray.mk #[0x04]) ++ ByteArray.mk (Array.mkArray 64 0xBE))]
def sampleTraceStr : String :=
  (NegotiationTrace.ofClientHello [.x25519, .secp256r1] sampleTraceShares (some .secp256r1) none).render

def checks : List Check :=
  [ { name := "handshake reaches connected through step"
    , ok := runE2E.st.handshake == .connected }
  , { name := "completion is reported"
    , ok := runE2E.completed }
  , { name := "no plaintext emitted during the handshake"
    , ok := runE2E.emitted.isEmpty }
  , { name := "server flight written to transport (SH, EE, Cert, CertVerify, Fin)"
    , ok := runE2E.outbound.length == 5 }
  , { name := "no error on the success path"
    , ok := !runE2E.errored }
  , { name := "transcript committed seven messages end-to-end"
    , ok := runE2E.st.transcript.eventCount == 7 }
  , { name := "negotiated suite recorded (chacha20-poly1305, not the AES the client listed first)"
    , ok := runE2E.st.negotiated.selectedSuite == some .chacha20Poly1305Sha256 }
  , { name := "secp256r1-only ClientHello reaches connected (P-256 ECDHE negotiated)"
    , ok := runE2EP256.st.handshake == .connected }
  , { name := "secp256r1 ClientHello records the P-256 group in negotiation state"
    , ok := runE2EP256.st.negotiated.selectedGroup == some .secp256r1 }
  , { name := "RFC 039: both groups offered, server preference picks x25519 (not client order)"
    , ok := runE2EBoth.st.negotiated.selectedGroup == some .x25519 && runE2EBoth.st.handshake == .connected }
  , { name := "RFC 039: duplicate key_share group is rejected, never connected"
    , ok := runDupKeyShare.st.handshake != .connected && runDupKeyShare.st.handshake.isTerminal }
  , { name := "RFC 039: x25519-only endpoint refuses a secp256r1-only client (policy enforced)"
    , ok := runP256ClientX25519OnlyServer.st.handshake != .connected
            && runP256ClientX25519OnlyServer.st.handshake.isTerminal }
  , { name := "RFC 039: that refusal never negotiated P-256 (no unauthorized group)"
    , ok := runP256ClientX25519OnlyServer.st.negotiated.selectedGroup == none }
  , { name := "RFC 039: unknown group dropped, secp256r1 share selected"
    , ok := runUnkP256.st.negotiated.selectedGroup == some .secp256r1 && runUnkP256.st.handshake == .connected }
  , { name := "RFC 039: duplicate secp256r1 key_share rejected, never connected"
    , ok := runDupP256.st.handshake != .connected && runDupP256.st.handshake.isTerminal }
  , { name := "RFC 039 §4.6: key_share group omitted from supported_groups → rejected"
    , ok := runKsNotInSg.st.handshake != .connected && runKsNotInSg.st.handshake.isTerminal }
  , { name := "RFC 039 §4.6: supported_groups present but no usable key_share → no-HRR fail"
    , ok := runSgNoKs.st.handshake != .connected && runSgNoKs.st.handshake.isTerminal }
  , { name := "RFC 039 §8.12: secp256r1 key_share with bad prefix rejected"
    , ok := runP256BadPrefix.st.handshake != .connected && runP256BadPrefix.st.handshake.isTerminal }
  , { name := "RFC 039 §8.12: secp256r1 key_share with bad length rejected"
    , ok := runP256BadLen.st.handshake != .connected && runP256BadLen.st.handshake.isTerminal }
  , { name := "RFC 039 §8.14: no-overlap (x25519-only vs P-256-only) → handshake_failure alert"
    , ok := hasAlert runP256ClientX25519OnlyServer .handshakeFailure }
  , { name := "RFC 039 §8.14: duplicate key_share group → illegal_parameter alert"
    , ok := hasAlert runDupKeyShare .illegalParameter }
  , { name := "RFC 039 §8.14: key_share omitted from supported_groups → illegal_parameter alert"
    , ok := hasAlert runKsNotInSg .illegalParameter }
  , { name := "RFC 039 §8.14: malformed P-256 key_share → illegal_parameter alert"
    , ok := hasAlert runP256BadPrefix .illegalParameter }
  , { name := "RFC 039 §4.9: trace surfaces the selected group id (secp256r1=23)"
    , ok := (sampleTraceStr.splitOn "selected=23").length == 2 }
  , { name := "RFC 039 §4.9: trace surfaces endpoint/offered group ids (x25519=29)"
    , ok := (sampleTraceStr.splitOn "29").length ≥ 2 }
  , { name := "RFC 039 §4.9: trace never leaks raw key_share bytes (0xBE=190 absent)"
    , ok := (sampleTraceStr.splitOn "190").length == 1 }
    -- negatives
  , { name := "malformed ClientHello fails, not connected"
    , ok := runMalformedCH.st.handshake.isTerminal && runMalformedCH.st.handshake != .connected }
  , { name := "malformed ClientHello emits no plaintext"
    , ok := runMalformedCH.emitted.isEmpty }
  , { name := "application data before connected is not delivered"
    , ok := runAppDataEarly.emitted.isEmpty && runAppDataEarly.st.handshake != .connected }
  , { name := "bad client Finished fails, never connected"
    , ok := runBadFinished.st.handshake != .connected && runBadFinished.st.handshake.isTerminal }
  , { name := "bad client Finished emits no plaintext"
    , ok := runBadFinished.emitted.isEmpty }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M5 end-to-end handshake (through step, fake crypto/transport):"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.EndToEnd

def main : IO UInt32 := Tests.EndToEnd.main
