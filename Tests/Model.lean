import Kroopt.Core.Step

/-!
# Tests.Model

Deterministic model test (RFC 014 §5): drives `Kroopt.Core.step` directly with
scripted input events and asserts the resulting state/action behaviour. No
sockets, no real time, no real crypto.

These behavioural checks complement the structural proofs in `Kroopt.Proofs`:
the proofs guarantee the invariants hold for *all* inputs; these tests pin down
the concrete M0 transitions so regressions are visible.
-/

namespace Tests.Model

open Kroopt
open Kroopt.Core

/-- A simple test harness: name + boolean condition. -/
structure Check where
  name : String
  ok : Bool

/-- The fixed connection/config used throughout the scripted tests. -/
def conn : ConnId := { value := 1, generation := 1 }
def cfg : ConfigGeneration := { value := 1 }

/-- A fresh handshaking state. -/
def s0 : State := State.initial conn cfg .sha256

/-- A `connected` state, optionally with one buffered plaintext record. -/
def connectedState (buffered : Option ByteArray) : State :=
  { s0 with handshake := .connected, pendingPlainOut := buffered }

/-- Count `emitPlaintext` actions in a step result (0 on error). -/
def countPlaintextEmits : StepResult → Nat
  | .ok (_, acts) => (acts.filter OutputAction.isPlaintextEmit).length
  | .error _      => 0

/-- Extract the handshake phase from a step result, if it succeeded. -/
def resultPhase : StepResult → Option HandshakeState
  | .ok (s, _) => some s.handshake
  | .error _   => none

/-- Does the result's action list contain a `closeTransport`? -/
def hasCloseTransport : StepResult → Bool
  | .ok (_, acts) => acts.any (fun a => match a with
                                        | .closeTransport _ _ => true
                                        | _ => false)
  | .error _ => false

def sampleBytes : ByteArray := ByteArray.mk #[104, 105]  -- "hi"

/-- The scripted checks. -/
def checks : List Check :=
  -- 1. No early plaintext: recv in `start` (not connected) emits nothing.
  [ { name := "recv before connected emits no plaintext"
    , ok := countPlaintextEmits (step s0 (.appRecvRequested conn)) == 0 }
  -- 2. send before connected fails cleanly into `failed`, no plaintext.
  , { name := "send before connected fails cleanly"
    , ok := (match resultPhase (step s0 (.appSend conn sampleBytes)) with
             | some (.failed _) => true | _ => false)
            && countPlaintextEmits (step s0 (.appSend conn sampleBytes)) == 0 }
  -- 3. recv in connected WITH a buffered record emits exactly one plaintext.
  , { name := "recv in connected delivers buffered plaintext"
    , ok := countPlaintextEmits
              (step (connectedState (some sampleBytes)) (.appRecvRequested conn)) == 1 }
  -- 4. recv in connected with NO buffer emits nothing (wouldBlock-like).
  , { name := "recv in connected with empty buffer emits nothing"
    , ok := countPlaintextEmits
              (step (connectedState none) (.appRecvRequested conn)) == 0 }
  -- 5. After delivery the buffer is cleared (no double-delivery).
  , { name := "buffered plaintext is cleared after delivery"
    , ok := (match step (connectedState (some sampleBytes)) (.appRecvRequested conn) with
             | .ok (s', _) => s'.pendingPlainOut.isNone
             | .error _    => false) }
  -- 6. appClose transitions to `closing` and routes a closeTransport.
  , { name := "graceful close routes closeTransport and enters closing"
    , ok := (resultPhase (step s0 (.appClose conn .graceful)) == some .closing)
            && hasCloseTransport (step s0 (.appClose conn .graceful)) }
  -- 7. transportEof before close_notify is a truncation failure, no plaintext.
  , { name := "EOF before close_notify is truncation failure"
    , ok := (match resultPhase (step (connectedState none) (.transportEof conn)) with
             | some (.failed _) => true | _ => false)
            && countPlaintextEmits (step (connectedState none) (.transportEof conn)) == 0 }
  -- 8. Terminal (failed) state is absorbing: any event leaves it unchanged.
  , { name := "terminal state is absorbing"
    , ok := (let term := { s0 with handshake := .failed .handshakeFailure }
             match step term (.appRecvRequested conn) with
             | .ok (s', acts) => (s'.handshake == term.handshake) && acts.isEmpty
             | .error _       => false) }
  -- 9. Determinism (observable): the same input twice yields the same phase
  --    and the same plaintext-emit count.
  , { name := "step is deterministic for a fixed input"
    , ok := (resultPhase (step s0 (.appClose conn .graceful))
               == resultPhase (step s0 (.appClose conn .graceful)))
            && (countPlaintextEmits (step s0 (.appClose conn .graceful))
               == countPlaintextEmits (step s0 (.appClose conn .graceful))) }
  ]

/-- Run all checks, print a report, and return nonzero on any failure. -/
def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M0 model tests (driving Kroopt.Core.step):"
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

end Tests.Model

/-- Entry point. -/
def main : IO UInt32 := Tests.Model.main
