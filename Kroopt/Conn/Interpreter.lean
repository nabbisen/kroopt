import Kroopt.Core.Step
import Kroopt.Crypto.Provider
import Kroopt.Conn.Transport

/-!
# Kroopt.Conn.Interpreter

The thin imperative interpreter (RFC 002 §5, RFC 010 §6). It executes the core's
`OutputAction` list over the transport and the crypto provider, and feeds results
back as `InputEvent`s — and it makes **no protocol decisions**. Every function
here dispatches on the `OutputAction` *variant* alone; none branches on the
handshake phase, chooses a cipher suite, derives a sequence number, or decides
whether plaintext is legal. That is the proof/runtime correspondence contract
made into a runtime artifact (RFC 010 §12): all protocol truth stays in
`Kroopt.Core.step`, which the proofs in `Kroopt.Proofs` constrain.

The driver is a fuel-bounded loop, so it can never spin on repeated `wouldBlock`
(RFC 010 §10).
-/

namespace Kroopt.Conn

open Kroopt (TlsError TransportError CryptoError)
open Kroopt.Core (State InputEvent OutputAction HandshakeInfo)
open Kroopt.Crypto (CryptoProvider)

/-- How many bytes a single `readTransport` requests. -/
def maxReadChunk : Nat := 16384

/-- The interpreter's bookkeeping — pending ciphertext, the one buffered
plaintext record for `recv`, accepted-plaintext accounting for `send`, and the
public metadata view. Protocol truth lives in the core `State`, never here
(RFC 010 §9). -/
structure RuntimeState where
  outbound       : ByteArray := ByteArray.mk #[]
  plaintextOut   : Option ByteArray := none
  acceptedBytes  : Nat := 0
  writeInterest  : Bool := false
  metadata       : Option HandshakeInfo := none
  lastError      : Option TlsError := none
  terminal       : Bool := false
  deriving Inhabited

/-- Try to push the pending ciphertext queue toward the transport, honouring
partial writes and `wouldBlock` (RFC 010 §4). Bytes already sent are removed from
the head of the queue, preserving order. -/
partial def drainOutbound (rt : RuntimeState) (tr : FakeTransport) : RuntimeState × FakeTransport :=
  if rt.outbound.isEmpty then (rt, tr)
  else
    match tr.send tr.fd rt.outbound with
    | (.sent n, tr') =>
        if n = 0 ∨ n ≥ rt.outbound.size then
          ({ rt with outbound := rt.outbound.extract n rt.outbound.size }, tr')
        else
          drainOutbound { rt with outbound := rt.outbound.extract n rt.outbound.size } tr'
    | (.wouldBlock, tr') => (rt, tr')
    | (.error e, tr') => ({ rt with lastError := some (.transport e), terminal := true }, tr')

/-- Execute one action (RFC 010 §6). Dispatches on the action **variant only** —
no protocol-state branching. Returns the updated runtime/transport and any
follow-up `InputEvent`s to feed back to the core. -/
def execAction (prov : CryptoProvider) (rt : RuntimeState) (tr : FakeTransport) :
    OutputAction → RuntimeState × FakeTransport × List InputEvent
  | .readTransport conn =>
      match tr.recv tr.fd maxReadChunk with
      | (.bytes b, tr')   => (rt, tr', [InputEvent.transportBytes conn b])
      | (.wouldBlock, tr') => (rt, tr', [])
      | (.eof, tr')        => (rt, tr', [InputEvent.transportEof conn])
      | (.error e, tr')    => ({ rt with lastError := some (.transport e) }, tr',
                               [InputEvent.transportEof conn])
  | .writeTransport _ b =>
      let (rt', tr') := drainOutbound { rt with outbound := rt.outbound ++ b } tr
      (rt', tr', [])
  | .enableWriteInterest _  => ({ rt with writeInterest := true }, tr.enableWrite tr.fd, [])
  | .disableWriteInterest _ => ({ rt with writeInterest := false }, tr.disableWrite tr.fd, [])
  | .callCrypto conn op req =>
      match prov.submit op req with
      | .ok r    => (rt, tr, [InputEvent.cryptoResult conn op r])
      | .error e => (rt, tr, [InputEvent.cryptoResult conn op (.failed e)])
  | .emitPlaintext _ b        => ({ rt with plaintextOut := some b }, tr, [])
  | .acceptPlaintextBytes _ n => ({ rt with acceptedBytes := rt.acceptedBytes + n }, tr, [])
  | .reportHandshakeComplete _ info => ({ rt with metadata := some info }, tr, [])
  | .reportError _ e          => ({ rt with lastError := some e, terminal := true }, tr, [])
  | .failWithAlert _ _        => ({ rt with terminal := true }, tr, [])
  | .closeTransport _ _       => ({ rt with terminal := true }, tr.closeConnection tr.fd, [])
  | .releaseSecret _          => (rt, tr, [])

/-- Execute a list of actions in order, accumulating follow-up events. -/
def execActions (prov : CryptoProvider) (rt : RuntimeState) (tr : FakeTransport)
    (acts : List OutputAction) : RuntimeState × FakeTransport × List InputEvent :=
  acts.foldl
    (fun (acc : RuntimeState × FakeTransport × List InputEvent) a =>
      let (rt', tr', evs) := execAction prov acc.1 acc.2.1 a
      (rt', tr', acc.2.2 ++ evs))
    (rt, tr, [])

/-- The fuel-bounded drive loop (RFC 010 §6, §10 — *never spin on wouldBlock*).
Process events FIFO, but feed each step's follow-up events **before** the
remaining external events, so a crypto/transport cascade completes in phase. -/
def driveEvents (prov : CryptoProvider) :
    Nat → State → RuntimeState → FakeTransport → List InputEvent →
    State × RuntimeState × FakeTransport
  | 0, core, rt, tr, _ => (core, rt, tr)
  | _, core, rt, tr, [] => (core, rt, tr)
  | fuel + 1, core, rt, tr, ev :: rest =>
      match Kroopt.Core.step core ev with
      | .error e => (core, { rt with lastError := some e, terminal := true }, tr)
      | .ok (core', acts) =>
          let (rt', tr', newEvs) := execActions prov rt tr acts
          driveEvents prov fuel core' rt' tr' (newEvs ++ rest)

/-- Default progress budget per external event (RFC 010 §7). -/
def progressBudget : Nat := 256

end Kroopt.Conn
