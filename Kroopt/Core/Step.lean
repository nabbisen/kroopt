import Kroopt.Error
import Kroopt.Core.State
import Kroopt.Core.Event
import Kroopt.Core.Action
import Kroopt.Core.RecordPath

/-!
# Kroopt.Core.Step

The pure verified core's transition function (RFC 002 §3).

```
step : State → InputEvent → Except TlsError (State × List OutputAction)
```

`step` is the **only** place protocol decisions are made (RFC 002 §1). The
interpreter executes the emitted `OutputAction` list and feeds results back as
`InputEvent`s; it never branches on handshake state to decide behaviour
(RFC 002 §5).

## M0 scope

This is the M0 skeleton: the correct *shape* and the *safety discipline*, with
no real TLS protocol logic yet (no ClientHello parsing, no key schedule, no
record path — those arrive at M1–M4). What M0 establishes and proves:

* terminal states are absorbing and emit nothing (RFC 013 §7);
* `emitPlaintext` / `acceptPlaintextBytes` are reachable only from `connected`
  (RFC 002 §7 — *no early plaintext*);
* `appSend` before `connected` consumes zero plaintext and fails cleanly;
* `transportEof` before close_notify is a truncation failure, not a clean close
  (RFC 013 §6).

The structural theorems over this `step` live in `Kroopt.Proofs`. As real
transitions are added in later milestones, those theorems must continue to hold
— that is the proof/runtime correspondence contract (RFC 002 §5, RFC 022 §7).
-/

namespace Kroopt.Core

open Kroopt (TlsError AlertDescription ProtocolError TransportError ResourceLimitError)

/-- The result of one core step: either a typed error, or a new state paired
with the ordered actions to execute. -/
abbrev StepResult := Except TlsError (State × List OutputAction)

/-- Fail terminally with an alert: move to `failed`, record the fatal close
state, drop any buffered plaintext, and emit the alert plus a typed error. No
plaintext is emitted on this path (RFC 013 §4, §7). -/
def failAlert (s : State) (a : AlertDescription) (e : TlsError) : StepResult :=
  .ok ({ s with handshake := .failed a
                closeState := .fatalSent a
                pendingPlainOut := none },
       [ OutputAction.failWithAlert s.connId a,
         OutputAction.reportError s.connId e ])

/-- Terminal absorbing step: terminal phases ignore further events, leaving the
state unchanged and emitting nothing (RFC 013 §7). -/
def absorbTerminal (s : State) : StepResult :=
  .ok (s, [])

/-- The core transition function (M0 shape — see module doc). -/
def step (s : State) (ev : InputEvent) : StepResult :=
  if s.handshake.isTerminal then
    -- Terminal phases are absorbing: no plaintext, no ordinary writes.
    absorbTerminal s
  else
    match ev with
    | .appRecvRequested _ =>
      if s.handshake.isConnected then
        -- Deliver one buffered authenticated record, if any (RFC 004 §9).
        match s.pendingPlainOut with
        | some b => .ok ({ s with pendingPlainOut := none },
                          [OutputAction.emitPlaintext s.connId b])
        | none   => .ok (s, [])
      else
        -- No plaintext before `connected`: nothing to deliver, no error.
        .ok (s, [])
    | .appSend _ b =>
      if s.handshake.isConnected then
        -- Connected: fragment, seal, and accept ownership (record write path).
        handleAppSend s b
      else
        -- Send before `connected` consumes zero plaintext and fails cleanly.
        failAlert s .unexpectedMessage (.protocol .illegalMessageForState)
    | .appClose _ mode =>
      -- Begin close, distinguishing the three modes (RFC 013 §5). Repeated close
      -- is idempotent: once a close is in progress, re-issue the transport close
      -- without regressing the close state (RFC 013 §7).
      if s.closeState = .open then
        match mode with
        | .graceful =>
            -- RFC 8446 §6.1 / RFC 037 §6: a graceful close from `connected` seals an encrypted
            -- close_notify (level warning = 1, description close_notify = 0) under the application
            -- write epoch and sends it before closing. The seal reuses the application-data AEAD-seal
            -- action; when its result returns (state `.closing`, closeState `.sentCloseNotify`) the
            -- record is written and the transport closed. Before `connected` there is no application
            -- epoch to seal under, so the transport is closed directly.
            match s.handshake with
            | .connected =>
                match s.writeEpoch.seq.next with
                | none => failAlert s .internalError (.protocol .sequenceOverflow)
                | some sq =>
                    let inner := ByteArray.mk #[(1 : UInt8), 0, ContentType.alert.toByte]
                    let sealMeta := writeMeta s
                    allocOpOrFail s .aeadSeal .application (some .write) (fun oid s =>
                    let s := { s with writeEpoch := { s.writeEpoch with seq := sq }
                                      handshake := .closing
                                      closeState := .sentCloseNotify
                                      pendingPlainOut := none }
                    .ok (s, [OutputAction.callCrypto s.connId oid
                               (CryptoOp.aeadSeal sealMeta (ByteArray.mk #[]) inner)]))
            | _ =>
                .ok ({ s with handshake := .closing
                              closeState := .sentCloseNotify
                              pendingPlainOut := none },
                     [OutputAction.closeTransport s.connId .graceful])
        | .fatal a =>
            -- Local fatal close: the optional fatal alert is the only post-failure
            -- transport write permitted (RFC 013 §7).
            .ok ({ s with handshake := .failed a
                          closeState := .fatalSent a
                          pendingPlainOut := none },
                 [ OutputAction.failWithAlert s.connId a,
                   OutputAction.closeTransport s.connId (.fatal a) ])
        | .abortive =>
            -- Abortive close: no TLS alert, just drop the transport.
            .ok ({ s with handshake := .closed
                          closeState := .transportClosed
                          pendingPlainOut := none },
                 [OutputAction.closeTransport s.connId .abortive])
      else
        .ok (s, [OutputAction.closeTransport s.connId mode])
    | .transportEof _ =>
      -- EOF before close_notify is truncation, never a graceful end (RFC 013 §6).
      .ok ({ s with handshake := .failed .closeNotify
                    closeState := .transportEofBeforeCloseNotify
                    pendingPlainOut := none },
           [OutputAction.reportError s.connId (.transport .eofBeforeCloseNotify)])
    | .timeout _ _ =>
      -- Handshake/idle budget elapsed: fail (RFC 019).
      failAlert s .internalError (.resourceLimit .handshakeTimeout)
    | .transportBytes _ b =>
      -- Inbound record path (RFC 004 §5): reassemble and frame a record.
      handleTransportBytes s b
    | .cryptoResult _ op r =>
      -- A requested crypto operation returned: drive the record/handshake path.
      handleCryptoResult s op r
    | .transportReadable _ =>
      -- Readiness is a hint: ask the interpreter to actually read.
      .ok (s, [OutputAction.readTransport s.connId])
    | .transportWritable _ =>
      -- Socket writable: the interpreter drains pending ciphertext; no core change.
      .ok (s, [])
    | .appFlush _ =>
      -- Flush is driven by the interpreter against pending output; no core change.
      .ok (s, [])

end Kroopt.Core
