import Kroopt.Core.Step
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

def keyShareEntry : List UInt8 := [0x00, 0x1d, 0, 4, 1, 2, 3, 4]
def extKeyShare : List UInt8 := [0, 51, 0, 10, 0, 8] ++ keyShareEntry
def extSupVer : List UInt8 := [0, 43, 0, 3, 2, 0x03, 0x04]
def extsBody : List UInt8 := extSupVer ++ extKeyShare

def u16be (n : Nat) : List UInt8 := [(n / 256).toUInt8, (n % 256).toUInt8]

def chBody : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x01] ++ [1, 0] ++ (u16be extsBody.length ++ extsBody)

def chMsg : List UInt8 :=
  [1] ++ [0, (chBody.length / 256).toUInt8, (chBody.length % 256).toUInt8] ++ chBody

/-- Wrap a handshake message in a TLSPlaintext record (outer type 22). -/
def record (body : List UInt8) : ByteArray :=
  b ([22, 0x03, 0x03] ++ u16be body.length ++ body)

def chRecord : ByteArray := record chMsg
def clientFinishedRecord : ByteArray := record ([20] ++ u16be 32 ++ List.replicate 32 0x55)

/-! ## Fake crypto provider (deterministic, purpose-aware) -/

def fakeCrypto : CryptoOp → CryptoResult
  | .ecdheX25519 _ => .sharedSecret ⟨1, 0⟩
  | .signCertificateVerify _ _ => .signature (b (List.replicate 64 0xCD))
  | .verifyFinished _ _ _ => .verified
  | .aeadSeal _ _ pt => .aeadSealed pt
  | .aeadOpen _ _ ct => .aeadOpened ct
  | .randomBytes _ => .randomBytes (b [])
  | .hkdfExtract _ => .hkdfSecret ⟨2, 0⟩
  | .hkdfExpandLabel _ _ => .hkdfSecret ⟨3, 0⟩

/-! ## Driver loop -/

structure Driver where
  st : State
  outbound : List ByteArray
  emitted : List ByteArray
  completed : Bool
  errored : Bool

def applyAction (d : Driver) : OutputAction → Driver × List InputEvent
  | .writeTransport _ bytes => ({ d with outbound := d.outbound ++ [bytes] }, [])
  | .callCrypto c op req => (d, [InputEvent.cryptoResult c op (fakeCrypto req)])
  | .reportHandshakeComplete _ _ => ({ d with completed := true }, [])
  | .emitPlaintext _ bytes => ({ d with emitted := d.emitted ++ [bytes] }, [])
  | .reportError _ _ => ({ d with errored := true }, [])
  | .failWithAlert _ _ => ({ d with errored := true }, [])
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
  driveFuel 64 fresh
    [InputEvent.transportBytes ⟨0, 0⟩ chRecord,
     InputEvent.transportBytes ⟨0, 0⟩ clientFinishedRecord]

/-! ## Negative scenarios -/

def malformedChRecord : ByteArray := record [1, 0, 0, 8, 0x03, 0x03, 0, 0]  -- truncated CH
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
  , { name := "negotiated suite recorded (aes128)"
    , ok := runE2E.st.negotiated.selectedSuite == some .aes128GcmSha256 }
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
