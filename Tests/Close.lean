import Kroopt.Core.Step
import Kroopt.Core.Alert
import Kroopt.Conn.TlsConn

/-!
# Tests.Close

Alert-mapping, close-state-machine, and terminal-discipline tests (RFC 013 §10):
graceful / fatal / abortive close, transport-EOF truncation, inbound
close_notify, post-terminal idempotence, and the centralized alert mapping.
-/

namespace Tests.Close

open Kroopt Kroopt.Core

structure Check where
  name : String
  ok : Bool

def bytesOf (l : List UInt8) : ByteArray := ByteArray.mk l.toArray
def conn0 : ConnId := ⟨0, 0⟩

def connectedState : State :=
  { State.initial conn0 ⟨0⟩ .sha256 with handshake := .connected }

/-- Connected with an outstanding record-open op, for the inbound-alert path. -/
def connectedWithOp : State :=
  let (_, s) := connectedState.allocOp .aeadOpen .application (some .read)
  s

def failedState : State :=
  { State.initial conn0 ⟨0⟩ .sha256 with handshake := .failed .internalError }

/-- A well-formed compatibility change_cipher_spec record: outer type 20, the single
0x01 payload (RFC 8446 §5). -/
def ccsRecord : ByteArray := bytesOf [20, 0x03, 0x03, 0, 1, 1]

def checks : List Check :=
  [ -- close state machine (RFC 013 §3, §5)
    { name := "graceful close → closing / sentCloseNotify"
    , ok := (match step connectedState (.appClose conn0 .graceful) with
             | .ok (s', _) => s'.handshake == .closing && s'.closeState == .sentCloseNotify
             | .error _ => false) }
  , { name := "fatal close → failed / fatalSent, emits the alert"
    , ok := (match step connectedState (.appClose conn0 (.fatal .handshakeFailure)) with
             | .ok (s', acts) =>
                 s'.handshake == .failed .handshakeFailure
                 && s'.closeState == .fatalSent .handshakeFailure
                 && acts.any (fun a => match a with
                       | .failWithAlert _ .handshakeFailure => true | _ => false)
             | .error _ => false) }
  , { name := "abortive close → closed / transportClosed, no alert"
    , ok := (match step connectedState (.appClose conn0 .abortive) with
             | .ok (s', acts) =>
                 s'.handshake == .closed && s'.closeState == .transportClosed
                 && acts.all (fun a => match a with
                       | .failWithAlert _ _ => false | _ => true)
             | .error _ => false) }
    -- transport EOF is truncation, not a clean close (RFC 013 §6)
  , { name := "transport EOF before close_notify is a truncation failure"
    , ok := (match step connectedState (.transportEof conn0) with
             | .ok (s', _) =>
                 (match s'.handshake with | .failed _ => true | _ => false)
                 && s'.closeState == .transportEofBeforeCloseNotify
             | .error _ => false) }
    -- inbound close_notify (RFC 013 §5)
  , { name := "inbound alert record → receivedCloseNotify (peer close)"
    , ok := (match step connectedWithOp
               (.cryptoResult conn0 ⟨0⟩ (.aeadOpened (bytesOf [0x01, 0x00, 21]))) with
             | .ok (s', _) => s'.closeState == .receivedCloseNotify
             | .error _ => false) }
  , { name := "inbound fatal alert → failed / fatalReceived, torn down abortively (RFC 037 §6)"
    , ok := (match step connectedWithOp
               (.cryptoResult conn0 ⟨0⟩ (.aeadOpened (bytesOf [2, 40, 21]))) with
             | .ok (s', acts) =>
                 s'.handshake.isTerminal
                 && (match s'.closeState with | .fatalReceived .handshakeFailure => true | _ => false)
                 && acts.any (fun a => match a with | .closeTransport _ .abortive => true | _ => false)
             | .error _ => false) }
  , { name := "inbound non-close_notify alert is never treated as a graceful close (RFC 037 §6)"
    , ok := (match step connectedWithOp
               (.cryptoResult conn0 ⟨0⟩ (.aeadOpened (bytesOf [2, 47, 21]))) with
             | .ok (s', _) =>
                 s'.handshake.isTerminal
                 && (match s'.closeState with | .receivedCloseNotify => false | _ => true)
             | .error _ => false) }
  , { name := "malformed inbound alert (not exactly two bytes) is a decode error (RFC 037 §6)"
    , ok := (match step connectedWithOp
               (.cryptoResult conn0 ⟨0⟩ (.aeadOpened (bytesOf [0x01, 21]))) with
             | .ok (s', _) => s'.handshake.isTerminal
             | .error _ => false) }
  , { name := "AlertDescription.ofByte decodes known codes and rejects unknown"
    , ok := (match AlertDescription.ofByte 0 with | some .closeNotify => true | _ => false)
            && (match AlertDescription.ofByte 40 with | some .handshakeFailure => true | _ => false)
            && (match AlertDescription.ofByte 47 with | some .illegalParameter => true | _ => false)
            && (match AlertDescription.ofByte 99 with | none => true | _ => false) }
    -- terminal idempotence / discipline (RFC 013 §7)
  , { name := "appClose in a terminal state is absorbed (idempotent)"
    , ok := (match step failedState (.appClose conn0 .graceful) with
             | .ok (s', acts) => s'.handshake == .failed .internalError && acts.isEmpty
             | .error _ => false) }
  , { name := "appSend in a terminal state is absorbed, accepts nothing"
    , ok := (match step failedState (.appSend conn0 (bytesOf [1, 2, 3])) with
             | .ok (_, acts) => acts.isEmpty
             | .error _ => false) }
  , { name := "no buffered plaintext survives a fatal close"
    , ok := (let s := { connectedState with pendingPlainOut := some (bytesOf [9]) }
             match step s (.appClose conn0 (.fatal .internalError)) with
             | .ok (s', _) => s'.pendingPlainOut.isNone
             | .error _ => false) }
    -- centralized alert mapping (RFC 013 §4)
  , { name := "parse error 'oversizedRecord' maps to record_overflow"
    , ok := alertForParseError .oversizedRecord == .recordOverflow }
  , { name := "parse error 'truncated' maps to decode_error"
    , ok := alertForParseError .truncated == .decodeError }
  , { name := "AEAD auth failure maps to bad_record_mac"
    , ok := (match alertForCryptoFailure .authFailed with
             | some .badRecordMac => true | _ => false) }
  , { name := "internal crypto failure sends no detailed alert"
    , ok := (alertForCryptoFailure .providerInternal).isNone }
  , { name := "every parse-error alert is fatal (never closeNotify)"
    , ok := [ParseError.truncated, .trailingBytes, .lengthOverflow, .valueOutOfRange,
              .oversizedRecord, .malformedVector, .malformedExtension, .invalidContentType,
              .invalidDer].all (fun e => alertLevel (alertForParseError e) == .fatal) }
    -- change_cipher_spec phase window (RFC 8446 §5)
  , { name := "compatibility CCS during the handshake is accepted and ignored (RFC 8446 §5)"
    , ok := (match step { State.initial conn0 ⟨0⟩ .sha256 with handshake := .sentServerHello }
                         (.transportBytes conn0 ccsRecord) with
             | .ok (s', acts) => s'.handshake == .sentServerHello && acts.isEmpty
             | .error _ => false) }
  , { name := "CCS before any ClientHello (start) is rejected (RFC 8446 §5)"
    , ok := (match step (State.initial conn0 ⟨0⟩ .sha256) (.transportBytes conn0 ccsRecord) with
             | .ok (s', _) => s'.handshake.isTerminal
             | .error _ => true) }
  , { name := "CCS after connected is rejected (RFC 8446 §5)"
    , ok := (match step connectedState (.transportBytes conn0 ccsRecord) with
             | .ok (s', _) => s'.handshake.isTerminal
             | .error _ => true) }
  ]

def connChecks : List Check :=
  -- close + idempotence through the public API
  let fd0 : Kroopt.Conn.FdKey := { fd := 1, generation := 1 }
  let c : Kroopt.Conn.TlsConn :=
    { core := connectedState, rt := {}, tr := { fd := fd0, inbound := [] }
      prov := Kroopt.Crypto.fakeProvider }
  [ { name := "TlsConn.close graceful reports closeStarted or closed"
    , ok := (match (c.close .graceful).2 with
             | .closeStarted => true | .closed => true | _ => false) }
  , { name := "TlsConn.close is idempotent (second close still terminal-safe)"
    , ok := (let (c1, _) := c.close .graceful
             match (c1.close .graceful).2 with
             | .error _ => false | _ => true) }
  , { name := "send after close accepts nothing"
    , ok := (let (c1, _) := c.close .abortive
             match (c1.send (bytesOf [1, 2, 3])).2 with
             | .wrote _ => false | _ => true) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M9 alerts + close + terminal policy tests:"
  for chk in (checks ++ connChecks) do
    if chk.ok then IO.println s!"  PASS  {chk.name}"
    else IO.println s!"  FAIL  {chk.name}"; failures := failures + 1
  let total := (checks ++ connChecks).length
  if failures == 0 then
    IO.println s!"\nAll {total} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {total} checks FAILED."
    return 1

end Tests.Close

def main : IO UInt32 := Tests.Close.main
