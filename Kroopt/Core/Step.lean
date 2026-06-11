import Kroopt.Error
import Kroopt.Core.State
import Kroopt.Core.Event
import Kroopt.Core.Action

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
    | .appSend _ _ =>
      if s.handshake.isConnected then
        -- M0: the record send path is not built yet; accept zero bytes.
        -- (At M2/M4 this fragments + seals; ownership is acknowledged via
        --  `acceptPlaintextBytes`, still only in `connected`.)
        .ok (s, [])
      else
        -- Send before `connected` consumes zero plaintext and fails cleanly.
        failAlert s .unexpectedMessage (.protocol .illegalMessageForState)
    | .appClose _ mode =>
      -- Begin close: stop accepting app data, route close through the transport.
      .ok ({ s with handshake := .closing
                    closeState := .sentCloseNotify
                    pendingPlainOut := none },
           [OutputAction.closeTransport s.connId mode])
    | .transportEof _ =>
      -- EOF before close_notify is truncation, never a graceful end (RFC 013 §6).
      .ok ({ s with handshake := .failed .closeNotify
                    closeState := .transportEofBeforeCloseNotify
                    pendingPlainOut := none },
           [OutputAction.reportError s.connId (.transport .eofBeforeCloseNotify)])
    | .timeout _ _ =>
      -- Handshake/idle budget elapsed: fail (RFC 019).
      failAlert s .internalError (.resourceLimit .handshakeTimeout)
    | _ =>
      -- M0: other events (transportBytes, readiness hints, cryptoResult, flush)
      -- are accepted with no protocol effect yet — shape placeholders that the
      -- M1–M4 milestones replace with real transitions.
      .ok (s, [])

end Kroopt.Core
