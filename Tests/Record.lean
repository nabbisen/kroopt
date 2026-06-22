import Kroopt.Core.Step
import Kroopt.Parse.Record

/-!
# Tests.Record

Unit and negative tests for the TLS 1.3 record model (RFC 004 §13). Pure: no
sockets, no real crypto — crypto results are *fed in* as `cryptoResult` events,
exactly as the interpreter will do later. These pin down the concrete record
behaviour the proofs guarantee is *safe* but do not fix to specific values:
header framing, oversize rejection, reassembly split points, inner content-type
validation, CCS accept/reject, and — crucially — that a fake AEAD-open success
buffers application plaintext while a fake AEAD-open failure buffers none and
goes terminal.
-/

namespace Tests.Record

open Kroopt Kroopt.Core Kroopt.Parse

structure Check where
  name : String
  ok : Bool

def bytes (l : List UInt8) : ByteArray := ByteArray.mk l.toArray

/-- A fresh connected state, as if the handshake had completed (M2 exercises the
record path directly; the real path to `connected` arrives at M4). -/
def connectedState : State :=
  let s := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
  -- a record-open operation is outstanding (id 0), as it is when its result
  -- arrives in the real read path — required by the RFC 008 §5 correlation guard
  let (_, s) := (s.allocOp .aeadOpen .application (some .read) ResourceLimits.standard.maxPendingCryptoOps).toOption.getD (⟨0⟩, s)
  { s with handshake := .connected }

/-- A protected application-data record on the wire: header (type 23, version,
length) followed by `body` bytes. -/
def appRecord (body : List UInt8) : ByteArray :=
  let len := body.length
  bytes ([23, 0x03, 0x03, (UInt8.ofNat (len / 256)), (UInt8.ofNat (len % 256))] ++ body)

/-- Run a single step and report whether plaintext got buffered. -/
def bufferedAfter (s : State) (ev : InputEvent) : Option ByteArray :=
  match step s ev with
  | .ok (s', _) => s'.pendingPlainOut
  | .error _    => none

def isTerminalAfter (s : State) (ev : InputEvent) : Bool :=
  match step s ev with
  | .ok (s', _) => s'.handshake.isTerminal
  | .error _    => false

def checks : List Check :=
  -- Record header parsing
  [ { name := "record header parses type/version/length"
    , ok := (match (Reader.ofBytes (appRecord [1,2,3,4])).takeRecordHeader with
             | .ok (hdr, _) => hdr.outerType == .applicationData && hdr.length == 4
             | .error _     => false) }
  , { name := "record header rejects oversize length (> 2^14+256)"
    , ok := (match (Reader.ofBytes (bytes [23, 0x03, 0x03, 0xFF, 0xFF])).takeRecordHeader with
             | .ok _    => false
             | .error _ => true) }
  , { name := "ContentType round-trips through its wire byte"
    , ok := ContentType.ofByte (ContentType.applicationData.toByte) == .applicationData
            && ContentType.ofByte (ContentType.handshake.toByte) == .handshake
            && ContentType.ofByte 99 == .invalid }
  -- Reassembly: tryTakeRecord needs the full record buffered
  , { name := "tryTakeRecord returns none until header is buffered"
    , ok := (match (Reader.ofBytes (bytes [23, 0x03])).tryTakeRecord with
             | .ok (none, _) => true
             | _             => false) }
  , { name := "tryTakeRecord returns none until body is buffered"
    , ok := (match (Reader.ofBytes (bytes [23, 0x03, 0x03, 0x00, 0x04, 1, 2])).tryTakeRecord with
             | .ok (none, _) => true
             | _             => false) }
  , { name := "tryTakeRecord yields the record once fully buffered"
    , ok := (match (Reader.ofBytes (appRecord [1,2,3,4])).tryTakeRecord with
             | .ok (some (hdr, body), _) => hdr.length == 4 && body.size == 4
             | _                         => false) }
  -- Inner plaintext parsing (post-decrypt): strip padding, read inner type
  , { name := "parseInnerPlaintext reads inner content type, strips padding"
    , ok := (match parseInnerPlaintext (bytes [0xDE, 0xAD, 23, 0, 0]) with
             | .ok inner => inner.ctype == .applicationData
                            && inner.content.size == 2 && inner.paddingZeros == 2
             | .error _  => false) }
  , { name := "parseInnerPlaintext on all-zeros is malformed"
    , ok := (match parseInnerPlaintext (bytes [0, 0, 0]) with
             | .ok _    => false
             | .error _ => true) }
  , { name := "parseInnerPlaintext rejects unknown inner type as invalid"
    , ok := (match parseInnerPlaintext (bytes [0xAA, 99]) with
             | .ok inner => inner.ctype == .invalid
             | .error _  => false) }
  -- CCS classification (RFC 004 §8)
  , { name := "classifyCcs accepts the single 0x01 compatibility record"
    , ok := classifyCcs (bytes [1]) == .allowedCompat }
  , { name := "classifyCcs rejects any other CCS body"
    , ok := classifyCcs (bytes [0]) == .rejected
            && classifyCcs (bytes [1, 1]) == .rejected
            && classifyCcs (bytes []) == .rejected }
  -- Record read path through `step`: transport bytes request an AEAD open
  , { name := "connected app-data record requests an AEAD open (callCrypto)"
    , ok := (match step connectedState (.transportBytes ⟨0,0⟩ (appRecord [9,9,9])) with
             | .ok (_, acts) => acts.any (fun a =>
                 match a with | .callCrypto _ _ _ => true | _ => false)
             | .error _      => false) }
  , { name := "partial inbound record asks to read more (no crypto yet)"
    , ok := (match step connectedState (.transportBytes ⟨0,0⟩ (bytes [23, 0x03])) with
             | .ok (_, acts) => acts.any (fun a =>
                 match a with | .readTransport _ => true | _ => false)
             | .error _      => false) }
  -- Fake AEAD open: success buffers app plaintext; failure buffers none + fatal
  , { name := "fake AEAD-open success buffers application plaintext"
    , ok := (bufferedAfter connectedState
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (bytes [0x41, 0x42, 23])))).isSome }
  , { name := "fake AEAD-open success buffers exactly the inner content"
    , ok := (match bufferedAfter connectedState
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (bytes [0x41, 0x42, 23]))) with
             | some b => b.size == 2
             | none   => false) }
  , { name := "fake AEAD-open FAILURE buffers no plaintext"
    , ok := (bufferedAfter connectedState
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ .verifyFailed)).isNone }
  , { name := "fake AEAD-open FAILURE is fatal (terminal)"
    , ok := isTerminalAfter connectedState (.cryptoResult ⟨0,0⟩ ⟨0⟩ .verifyFailed) }
  , { name := "inner alert from a decrypted record begins close (not buffered)"
    , ok := (bufferedAfter connectedState
               (.cryptoResult ⟨0,0⟩ ⟨0⟩ (.aeadOpened (bytes [21])))).isNone }
  -- Write path: a connected send requests a seal and accepts ownership
  , { name := "connected send requests a seal and accepts plaintext bytes"
    , ok := (match step connectedState (.appSend ⟨0,0⟩ (bytes [1,2,3])) with
             | .ok (_, acts) =>
                 acts.any (fun a => match a with | .callCrypto _ _ _ => true | _ => false)
                 && acts.any (fun a => match a with | .acceptPlaintextBytes _ _ => true | _ => false)
             | .error _ => false) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M2 record-model tests (Kroopt.Core record path):"
  for c in checks do
    if c.ok then
      IO.println s!"  PASS  {c.name}"
    else
      IO.println s!"  FAIL  {c.name}"
      failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Record

def main : IO UInt32 := Tests.Record.main
