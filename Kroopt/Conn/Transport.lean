import Kroopt.Error

/-!
# Kroopt.Conn.Transport

The abstract transport interface kroopt drives (RFC 010 §6, §10.1). kroopt
performs no syscalls and names no concrete transport: it requires only a generic
non-blocking byte channel — `recv`, `send`, `enableWrite`/`disableWrite`,
`closeConnection`, and a generation-protected `FdKey`. **kroopt requires no
TLS-specific API from the transport** (Requirements §2.3); if it did, the
boundary would be violated.

That contract is the `Transport` typeclass below. `FakeTransport` is the
deterministic, pure in-model *instance* used by the tests, which makes the
interpreter fully deterministic without IO or sockets. A real deployment
supplies another instance — for example a thin adapter over a non-blocking I/O
reactor such as iotakt — that lifts the very same action-mapping
(`Kroopt.Conn.Interpreter`) into IO calls. Such an adapter carries no protocol
logic, so it adds nothing the proofs depend on. (The real transport adapter is
the deferred binding — Requirements §21 v0.3.)
-/

namespace Kroopt.Conn

open Kroopt (TransportError)

/-- A generation-protected fd identity, mirroring iotakt's `FdKey` (RFC 010 §8).
A transport event whose generation does not match is stale and ignored. -/
structure FdKey where
  fd : UInt64
  generation : UInt64
  deriving DecidableEq, Repr, Inhabited

/-- The outcome of a non-blocking `recv` (readiness is only a hint, so a read may
still report `wouldBlock`). -/
inductive RecvOutcome where
  | bytes (b : ByteArray)
  | wouldBlock
  | eof
  | error (e : TransportError)
  deriving Inhabited

/-- The outcome of a non-blocking `send`: a (possibly partial) accepted prefix
length, a `wouldBlock`, or a transport error. -/
inductive SendOutcome where
  | sent (n : Nat)
  | wouldBlock
  | error (e : TransportError)
  deriving Inhabited

/-- The abstract transport interface kroopt requires (RFC 010 §6, §10.1): a
non-blocking byte channel with a generation-protected identity. The interpreter
is generic over *this interface* — it never names a concrete transport. The
in-model `FakeTransport` is one instance; a real I/O reactor (e.g. iotakt)
provides another. -/
class Transport (τ : Type) where
  fd              : τ → FdKey
  recv            : τ → FdKey → Nat → RecvOutcome × τ
  send            : τ → FdKey → ByteArray → SendOutcome × τ
  enableWrite     : τ → FdKey → τ
  disableWrite    : τ → FdKey → τ
  closeConnection : τ → FdKey → τ

/-- A deterministic, pure fake transport (RFC 014 §3) — the in-model `Transport`
instance. `inbound` is a queue of chunks delivered one per `recv`; `outbound` logs everything written; the
`writeSchedule` models partial writes and back-pressure so retry/ordering tests
are reproducible. `eofAfter` delivers EOF once `inbound` is exhausted and that
many further reads have occurred. -/
structure FakeTransport where
  fd            : FdKey
  inbound       : List ByteArray
  outbound      : List ByteArray := []
  writeSchedule : List SendOutcome := []
  writeInterest : Bool := false
  closed        : Bool := false
  emptyReads    : Nat := 0
  eofAfter      : Option Nat := none
  deriving Inhabited

namespace FakeTransport

/-- Non-blocking receive: deliver the next inbound chunk, or `wouldBlock` / `eof`
once the queue is drained according to `eofAfter`. -/
def recv (t : FakeTransport) (_ : FdKey) (_max : Nat) : RecvOutcome × FakeTransport :=
  match t.inbound with
  | chunk :: rest => (.bytes chunk, { t with inbound := rest })
  | [] =>
      match t.eofAfter with
      | some n => if t.emptyReads ≥ n then (.eof, t)
                  else (.wouldBlock, { t with emptyReads := t.emptyReads + 1 })
      | none   => (.wouldBlock, { t with emptyReads := t.emptyReads + 1 })

/-- Non-blocking send: consult the write schedule for a partial/blocked outcome,
otherwise accept all bytes. The accepted prefix is appended to `outbound` so
ordering can be checked. -/
def send (t : FakeTransport) (_ : FdKey) (b : ByteArray) : SendOutcome × FakeTransport :=
  match t.writeSchedule with
  | .wouldBlock :: rest => (.wouldBlock, { t with writeSchedule := rest })
  | .error e :: rest    => (.error e, { t with writeSchedule := rest })
  | .sent n :: rest =>
      let k := min n b.size
      (.sent k, { t with writeSchedule := rest,
                         outbound := t.outbound ++ [b.extract 0 k] })
  | [] => (.sent b.size, { t with outbound := t.outbound ++ [b] })

def enableWrite (t : FakeTransport) (_ : FdKey) : FakeTransport :=
  { t with writeInterest := true }

def disableWrite (t : FakeTransport) (_ : FdKey) : FakeTransport :=
  { t with writeInterest := false }

def closeConnection (t : FakeTransport) (_ : FdKey) : FakeTransport :=
  { t with closed := true }

/-- Total bytes written to the wire, in order. -/
def writtenBytes (t : FakeTransport) : ByteArray :=
  t.outbound.foldl (· ++ ·) (ByteArray.mk #[])

end FakeTransport

/-- `FakeTransport` as the deterministic in-model instance of the `Transport`
interface. -/
instance : Transport FakeTransport where
  fd              := FakeTransport.fd
  recv            := FakeTransport.recv
  send            := FakeTransport.send
  enableWrite     := FakeTransport.enableWrite
  disableWrite    := FakeTransport.disableWrite
  closeConnection := FakeTransport.closeConnection

end Kroopt.Conn
