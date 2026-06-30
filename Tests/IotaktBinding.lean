import Kroopt.Conn.Transport
import Kroopt.Core.Event

/-!
# Tests.IotaktBinding

Binding **translation reference** for the iotakt boundary, transcribed from the **accepted** iotakt
v0.13.1-dev consumer review (`handoff/iotakt-review-orders.md` + the iotakt team's response §O11; surface
re-confirmed current at iotakt 0.14.5, one RFC 061 namespace rename). It transcribes the iotakt API surface
the review delivered and gives the pure translation the review *corrected*: the `FdKey` shape (O5), the extra
`ReadResult`/`WriteResult` cases (O7/O9), the `IoEvent` classification (O9), and the result→outcome mapping.
These translations are pure and are unit-tested exhaustively here.

**Ownership (RFC 015 / RFC 009 reconcile, 2026-06-30).** The real iotakt adapter is **jemmet's**, not
kroopt's: `Jemmet/Conn/IotaktTransport.lean` instantiates kroopt's `Transport` over `IotaktRuntime.*`, and the
jemmet→iotakt edge lives there. **kroopt declares no iotakt edge** — its release sidecar lists only the
vendored HACL\* source, and RFC 030 records "no iotakt pin." kroopt ships the generic `TlsConn` over the
abstract `Transport`; this file is a *reference* jemmet's adapter implements against, **not** a future
kroopt-owned `Kroopt/Conn/IotaktTransport.lean` (which would re-introduce the very edge the provenance graph
excludes).

This lives under `Tests/` and depends only on `Kroopt.Conn.Transport`; the transcribed `IotaktSpec` types
stand in for the real iotakt surface, and **no real iotakt IO is invoked** — so kroopt's build and proofs
carry no iotakt dependency. What is NOT here: the live IO driver loop and wire interop — those are jemmet's
`IotaktTransport` over the real `IotaktRuntime.Loop` (`runStepAuto` + `recvAck`/`sendAck`, per the review
skeleton reproduced at the foot of this file), validated at the three-project standup
(`scripts/tls-interop.sh` / `https-e2e.sh`). What IS here: the boundary semantics, isolated and tested, so
jemmet's adapter is a faithful instantiation rather than a fresh derivation.
-/

namespace Tests.IotaktBinding

open Kroopt Kroopt.Conn Kroopt.Core

/-! ## iotakt API surface — transcribed verbatim from the review §O11 (replace with `import Iotakt`) -/
namespace IotaktSpec

abbrev RawFd := Int          -- kernel fd, non-negative
abbrev FdGeneration := Nat

structure FdKey where
  raw : RawFd
  gen : FdGeneration
  deriving Repr, DecidableEq, Inhabited

inductive IoErrno
  | again | connReset | pipe | other (code : Int)
  deriving Repr, DecidableEq, Inhabited

inductive IoEvent
  | readable | writable | eof | hangup | error (e : IoErrno)
  deriving Repr, Inhabited

inductive LoopEvent
  | newConnection (key : FdKey) (rawFd : RawFd)
  | dataReady (key : FdKey) (event : IoEvent)
  | tick (now : Nat)

inductive ReadResult
  | bytes (data : ByteArray) | wouldBlock | eof | interrupted | error (errno : IoErrno)

inductive WriteResult
  | wrote (n : USize) | wouldBlock | interrupted | closed | error (errno : IoErrno)

end IotaktSpec

/-! ## Translation layer (O5/O7/O9) -/

/-- O5: iotakt `FdKey { raw : Int, gen : Nat }` → kroopt `FdKey { fd, generation : UInt64 }`. `raw` is a
kernel fd, so it is non-negative; `Int.toNat` clamps any (impossible) negative to 0 defensively. kroopt
keeps its own `FdKey` so the `Transport` contract stays transport-agnostic. -/
def toKrooptFdKey (k : IotaktSpec.FdKey) : Kroopt.Conn.FdKey :=
  { fd := k.raw.toNat.toUInt64, generation := k.gen.toUInt64 }

/-- Map an iotakt `IoErrno` to kroopt's coarse, redaction-safe `TransportError`. -/
def errnoToTransportError : IotaktSpec.IoErrno → TransportError
  | .connReset  => .resetByPeer
  | .pipe       => .brokenPipe
  | .again      => .generic        -- EAGAIN is surfaced as wouldBlock upstream, not as an error
  | .other _    => .generic

/-- One iotakt read result becomes either a kroopt `RecvOutcome` or a retry instruction (the adapter
loops on `interrupted`/EINTR rather than surfacing it). -/
inductive RecvStep
  | outcome (o : RecvOutcome)
  | retry

/-- O7/O9: classify an iotakt `ReadResult`. `interrupted` → retry; everything else maps to a
`RecvOutcome` the existing interpreter already consumes (it turns `.error`/`.eof` into a terminal
`transportEof`). -/
def classifyRead : IotaktSpec.ReadResult → RecvStep
  | .bytes b      => .outcome (.bytes b)
  | .wouldBlock   => .outcome .wouldBlock
  | .eof          => .outcome .eof
  | .interrupted  => .retry
  | .error e      => .outcome (.error (errnoToTransportError e))

/-- One iotakt write result becomes either a kroopt `SendOutcome` or a retry instruction. -/
inductive WriteStep
  | outcome (o : SendOutcome)
  | retry

/-- O7: classify an iotakt `WriteResult`. `interrupted` → retry; `closed` (peer/socket gone under a
write) → a terminal transport error (`brokenPipe`); `wrote n` carries the accepted-prefix count that
drives the keep-the-suffix / advance-`offset` strategy. -/
def classifyWrite : IotaktSpec.WriteResult → WriteStep
  | .wrote n      => .outcome (.sent n.toNat)
  | .wouldBlock   => .outcome .wouldBlock
  | .interrupted  => .retry
  | .closed       => .outcome (.error .brokenPipe)
  | .error e      => .outcome (.error (errnoToTransportError e))

/-- O9: map an iotakt readiness/closure `IoEvent` to the kroopt `InputEvent`s the driver feeds for a
connection. `eof`/`hangup` both become `transportEof` (the core treats EOF-before-`close_notify` as
truncation); `error` is surfaced as `transportEof` too, with the typed error captured via the
`recvAck` path's `RecvOutcome.error` (interpreter records `lastError`). -/
def ioEventToInputs (conn : ConnId) : IotaktSpec.IoEvent → List InputEvent
  | .readable  => [InputEvent.transportReadable conn]
  | .writable  => [InputEvent.transportWritable conn]
  | .eof       => [InputEvent.transportEof conn]
  | .hangup    => [InputEvent.transportEof conn]
  | .error _   => [InputEvent.transportEof conn]

/-! ## The staging `Transport` instance

`IotaktConn` is the per-connection state the IO driver stages bytes into. The pure interpreter pulls
reads via `Transport.recv` (from `inbound`) and pushes writes via `Transport.send` (into `outbound`); the
driver performs the real `recvAck`/`sendAck` around it. This is the `SocketReactor` shape with the iotakt
`FdKey` translated in. One loop multiplexes many of these (O12-#5), keyed by `FdKey`. -/
structure IotaktConn where
  key           : IotaktSpec.FdKey
  inbound       : ByteArray := ByteArray.empty
  outbound      : ByteArray := ByteArray.empty
  pendingEof    : Bool := false
  writeInterest : Bool := false
  deriving Inhabited

instance : Transport IotaktConn where
  fd t := toKrooptFdKey t.key
  recv t _ _ :=
    if t.inbound.isEmpty then
      (if t.pendingEof then (.eof, t) else (.wouldBlock, t))
    else (.bytes t.inbound, { t with inbound := ByteArray.empty })
  send t _ b := (.sent b.size, { t with outbound := t.outbound ++ b })
  enableWrite t _  := { t with writeInterest := true }
  disableWrite t _ := { t with writeInterest := false }
  closeConnection t _ := t

/-! ## Unit tests for the translation layer -/

def conn0 : ConnId := ⟨0, 0⟩

def teTag : TransportError → String
  | .eofBeforeCloseNotify => "eofBeforeCloseNotify"
  | .resetByPeer => "resetByPeer"
  | .brokenPipe => "brokenPipe"
  | .generic => "generic"

def recvTag : RecvStep → String
  | .retry => "retry"
  | .outcome .wouldBlock => "wouldBlock"
  | .outcome .eof => "eof"
  | .outcome (.bytes b) => "bytes:" ++ toString b.size
  | .outcome (.error e) => "error:" ++ teTag e

def writeTag : WriteStep → String
  | .retry => "retry"
  | .outcome .wouldBlock => "wouldBlock"
  | .outcome (.sent n) => "sent:" ++ toString n
  | .outcome (.error e) => "error:" ++ teTag e

def inputTag : InputEvent → String
  | .transportReadable _ => "readable"
  | .transportWritable _ => "writable"
  | .transportEof _ => "eof"
  | .transportBytes _ _ => "bytes"
  | _ => "other"

/-- A staged connection used in the Transport-instance checks. -/
def stagedConn (bytes : ByteArray) (eof : Bool) : IotaktConn :=
  { key := { raw := 7, gen := 2 }, inbound := bytes, pendingEof := eof }

def recvTagOf (t : IotaktConn) : String :=
  match (Transport.recv t (Transport.fd t) 4096).1 with
  | .bytes b => "bytes:" ++ toString b.size
  | .wouldBlock => "wouldBlock"
  | .eof => "eof"
  | .error _ => "error"

def checks : List (String × Bool) :=
  let bs := ByteArray.mk #[1, 2, 3]
  [ -- O5: FdKey translation
    ("fdkey raw/gen → fd/generation",
      (toKrooptFdKey { raw := 5, gen := 3 }) == ({ fd := 5, generation := 3 } : Kroopt.Conn.FdKey)),
    ("fdkey clamps a negative raw to 0",
      (toKrooptFdKey { raw := -1, gen := 0 }).fd == 0),
    ("fdkey large gen preserved",
      (toKrooptFdKey { raw := 1000, gen := 4294967296 }).generation == 4294967296),
    -- O7/O9: ReadResult classification (all five cases)
    ("read bytes → outcome bytes", recvTag (classifyRead (.bytes bs)) == "bytes:3"),
    ("read wouldBlock → outcome wouldBlock", recvTag (classifyRead .wouldBlock) == "wouldBlock"),
    ("read eof → outcome eof", recvTag (classifyRead .eof) == "eof"),
    ("read interrupted → retry", recvTag (classifyRead .interrupted) == "retry"),
    ("read error connReset → resetByPeer", recvTag (classifyRead (.error .connReset)) == "error:resetByPeer"),
    ("read error pipe → brokenPipe", recvTag (classifyRead (.error .pipe)) == "error:brokenPipe"),
    ("read error other → generic", recvTag (classifyRead (.error (.other 13))) == "error:generic"),
    -- O7: WriteResult classification (all five cases)
    ("write wrote n → sent n", writeTag (classifyWrite (.wrote 12)) == "sent:12"),
    ("write wouldBlock → outcome wouldBlock", writeTag (classifyWrite .wouldBlock) == "wouldBlock"),
    ("write interrupted → retry", writeTag (classifyWrite .interrupted) == "retry"),
    ("write closed → brokenPipe (terminal)", writeTag (classifyWrite .closed) == "error:brokenPipe"),
    ("write error connReset → resetByPeer", writeTag (classifyWrite (.error .connReset)) == "error:resetByPeer"),
    -- O9: IoEvent → InputEvent classification
    ("event readable → transportReadable",
      (ioEventToInputs conn0 .readable).map inputTag == ["readable"]),
    ("event writable → transportWritable",
      (ioEventToInputs conn0 .writable).map inputTag == ["writable"]),
    ("event eof → transportEof", (ioEventToInputs conn0 .eof).map inputTag == ["eof"]),
    ("event hangup → transportEof (truncation)", (ioEventToInputs conn0 .hangup).map inputTag == ["eof"]),
    ("event error → transportEof", (ioEventToInputs conn0 (.error .connReset)).map inputTag == ["eof"]),
    -- Staging Transport instance
    ("staging fd is the translated key",
      Transport.fd (stagedConn ByteArray.empty false) == ({ fd := 7, generation := 2 } : Kroopt.Conn.FdKey)),
    ("staging recv with bytes → bytes", recvTagOf (stagedConn bs false) == "bytes:3"),
    ("staging recv empty, no eof → wouldBlock", recvTagOf (stagedConn ByteArray.empty false) == "wouldBlock"),
    ("staging recv empty, pendingEof → eof", recvTagOf (stagedConn ByteArray.empty true) == "eof"),
    ("staging send accumulates outbound",
      (Transport.send (stagedConn ByteArray.empty false) (Transport.fd (stagedConn ByteArray.empty false)) bs).2.outbound.size == 3),
    ("staging enableWrite sets interest",
      (Transport.enableWrite (stagedConn ByteArray.empty false) (Transport.fd (stagedConn ByteArray.empty false))).writeInterest == true) ]

def main : IO Unit := do
  let failed := checks.filter (fun c => !c.2)
  if failed.isEmpty then
    IO.println s!"All {checks.length} checks passed"
  else
    for f in failed do IO.println s!"FAILED: {f.1}"
    IO.Process.exit 1

end Tests.IotaktBinding

/-
Driver loop, for the real binding (review §O11 skeleton). Wired when iotakt v0.13.1-dev is in the build:

  loop ← EventLoop.create cfg
  loop ← (EventLoop.addListener loop port).1
  repeat:
    (loop, events) ← EventLoop.runStepAuto loop
    for ev in events:
      | newConnection key _      => conns[key] ← create kroopt TlsConn (toKrooptFdKey key)
      | dataReady key .readable  => (loop, rr) ← EventLoop.recvAck loop key 16384
                                    classifyRead rr → retry (loop recvAck) | stage bytes / mark eof|error
                                    run kroopt progress; drain its writeTransport via sendAck (advance offset)
      | dataReady key .writable  => drain conns[key].outbound via sendAck; disableWrite when empty
      | dataReady key .eof/.hangup => feed transportEof (truncation if pre-close_notify)
      | dataReady key (.error e) => surface via the recvAck error path
      | tick now                 => optional handshake-timeout bookkeeping
      | closeTransport action    => EventLoop.closeConnection loop key; drop conns[key]
-/

def main (args : List String) : IO Unit := Tests.IotaktBinding.main
