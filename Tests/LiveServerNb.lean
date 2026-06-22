import Kroopt.Conn.Interpreter
import Kroopt.Conn.Record13
import Kroopt.Crypto.RealProvider
import Kroopt.Crypto.Hacl
import Tests.RealFixtures

/-!
# Tests.LiveServerNb

The production-shaped I/O path for the live TLS 1.3 server: where `Tests.LiveServer` does **blocking**
reads in a hand-rolled push driver, this drives the verified core + production interpreter through a
**non-blocking, readiness-driven reactor** — the RFC 010 §6 progress loop, the shape a real `iotakt`
adapter takes (Requirements §2.3, §21 v0.3).

The seam is the `Transport` typeclass the interpreter is already generic over. `SocketReactor` is a real
(IO-backed) `Transport` instance: a `poll`/non-blocking-`recv`/non-blocking-`send` reactor fills its
inbound buffer and drains its outbound buffer in IO, while the *pure* interpreter pulls bytes via
`Transport.recv` (turning the core's `readTransport` actions into `transportBytes`) and pushes via
`Transport.send`. Readiness is only a hint: a `recv` may still report `wouldBlock`, partial writes are
retried on the next writable poll, and the core reassembles partial records by asking to read more. No
protocol logic lives in the reactor — it only moves bytes, exactly as RFC 010 requires.
-/

namespace Tests.LiveServerNb

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto Tests.RealFixtures

@[extern "kroopt_sock_close"]           opaque sockClose (fd : UInt32) : IO Unit
@[extern "kroopt_sock_listen"]          opaque sockListen (path : String) : IO UInt32
@[extern "kroopt_sock_accept"]          opaque sockAccept (lfd : UInt32) : IO UInt32
@[extern "kroopt_sock_set_nonblocking"] opaque sockSetNonblocking (fd : UInt32) : IO Unit
@[extern "kroopt_sock_recv_nb"]         opaque sockRecvNb (fd : UInt32) (n : UInt32) : IO ByteArray
@[extern "kroopt_sock_send_nb"]         opaque sockSendNb (fd : UInt32) (buf : ByteArray) : IO UInt64
@[extern "kroopt_sock_poll"]            opaque sockPoll (fd : UInt32) (wantWrite : UInt8) (timeoutMs : UInt32) : IO UInt32

def conn0 : ConnId := ⟨0, 0⟩

/-- A real, IO-backed `Transport` instance. The reactor fills `inbound` (bytes read off the socket) and
drains `outbound` (bytes the core authorised); the *pure* interpreter pulls/pushes through these. `recv`
reports `wouldBlock` when the reactor has not buffered anything — readiness is a hint. -/
structure SocketReactor where
  fdKey         : FdKey
  inbound       : ByteArray := ByteArray.empty
  outbound      : ByteArray := ByteArray.empty
  writeInterest : Bool := false
  deriving Inhabited

instance : Transport SocketReactor where
  fd t := t.fdKey
  recv t _ _ :=
    if t.inbound.isEmpty then (.wouldBlock, t)
    else (.bytes t.inbound, { t with inbound := ByteArray.empty })
  send t _ b := (.sent b.size, { t with outbound := t.outbound ++ b })
  enableWrite t _ := { t with writeInterest := true }
  disableWrite t _ := { t with writeInterest := false }
  closeConnection t _ := t

/-- Drain the reactor's outbound buffer to the socket with a non-blocking `send`, retrying partial
writes on subsequent writable polls. Bounded by fuel so a stuck peer cannot spin forever. -/
partial def flushOutbound (fd : UInt32) (tr : SocketReactor) (fuel : Nat := 8) : IO SocketReactor := do
  if tr.outbound.isEmpty then pure tr
  else match fuel with
  | 0 => pure tr
  | fuel + 1 =>
    let n ← sockSendNb fd tr.outbound
    if n == 0xFFFFFFFFFFFFFFFF then pure tr          -- transport error: let the loop terminate
    else if n == 0 then                              -- wouldBlock: wait for writable, then retry
      let _ ← sockPoll fd 1 2000
      flushOutbound fd tr fuel
    else
      let k := n.toNat
      flushOutbound fd { tr with outbound := tr.outbound.extract k tr.outbound.size } fuel

/-- Read one non-blocking chunk into the reactor's inbound buffer if the socket is readable. Returns the
updated reactor and whether EOF was seen. -/
def pumpInbound (fd : UInt32) (tr : SocketReactor) : IO (SocketReactor × Bool) := do
  let raw ← sockRecvNb fd 4096
  let status := if raw.size == 0 then (3 : UInt8) else raw.get! 0
  match status with
  | 0 => pure ({ tr with inbound := tr.inbound ++ raw.extract 1 raw.size }, false)  -- data
  | 2 => pure (tr, true)                                                            -- eof
  | _ => pure (tr, false)                                                           -- wouldBlock/error

/-- After feeding fresh bytes, the core frames one record per `transportBytes` and keeps any trailing
bytes buffered. A non-blocking `recv` returns chunks that may bundle several records (unlike a
one-record-at-a-time blocking read), so drain the buffer by re-driving with empty `transportBytes` while
the core keeps consuming complete records — stopping when only a partial record (or nothing) remains. -/
partial def drainBuffered (prov : CryptoProvider)
    (core : State) (rt : RuntimeState) (tr : SocketReactor) (fuel : Nat) :
    State × RuntimeState × SocketReactor :=
  match fuel with
  | 0 => (core, rt, tr)
  | fuel + 1 =>
    if core.inboundCiphertext.isEmpty then (core, rt, tr)
    else
      let before := core.inboundCiphertext.size
      let (c, r, t) := driveEvents prov 2048 core rt tr [InputEvent.transportBytes conn0 ByteArray.empty]
      if c.inboundCiphertext.size ≥ before then (c, r, t)   -- no progress: partial record, await more
      else drainBuffered prov c r t fuel

/-- The readiness-driven progress loop: poll, read what is ready, advance the core (which pulls the
buffered bytes via `Transport.recv` and pushes its flight via `Transport.send`), flush, repeat — until
`connected`, a terminal state, EOF, or fuel/timeout. -/
partial def reactorToConnected (fd : UInt32) (prov : CryptoProvider)
    (core : State) (rt : RuntimeState) (tr : SocketReactor) (fuel : Nat) :
    IO (State × RuntimeState × SocketReactor) := do
  match fuel with
  | 0 => pure (core, rt, tr)
  | fuel + 1 =>
    match core.handshake with
    | .connected => pure (core, rt, tr)
    | .failed _  => pure (core, rt, tr)
    | .closed    => pure (core, rt, tr)
    | _ =>
      let tr ← flushOutbound fd tr
      let wantWrite : UInt8 := if tr.outbound.isEmpty then 0 else 1
      let mask ← sockPoll fd wantWrite 2000
      if mask == 0 then pure (core, rt, tr)            -- timeout: peer stalled
      else do
        let (tr, eof) ← if mask &&& 1 != 0 then pumpInbound fd tr else pure (tr, false)
        let ev := if eof then [InputEvent.transportEof conn0]
                  else [InputEvent.transportReadable conn0]
        let (core', rt', tr') := driveEvents prov 2048 core rt tr ev
        let (core', rt', tr') := drainBuffered prov core' rt' tr' 16
        let tr' ← flushOutbound fd tr'
        reactorToConnected fd prov core' rt' tr' fuel

/-- Obtain one delivered application record: drain anything already buffered in the core (app data can
arrive bundled with the client's Finished in a single chunk), request delivery, and if nothing came,
poll for fresh bytes and retry. -/
partial def reactorRecvApp (fd : UInt32) (prov : CryptoProvider)
    (core : State) (rt : RuntimeState) (tr : SocketReactor) (fuel : Nat) :
    IO (State × RuntimeState × SocketReactor) := do
  match fuel with
  | 0 => pure (core, rt, tr)
  | fuel + 1 =>
    let (core, rt, tr) := drainBuffered prov core rt tr 16
    let (core, rt, tr) := driveEvents prov 2048 core rt tr [InputEvent.appRecvRequested conn0]
    match rt.plaintextOut with
    | some _ => pure (core, rt, tr)
    | none =>
        let mask ← sockPoll fd 0 1500
        if mask == 0 then pure (core, rt, tr)
        else do
          let (tr, _eof) ← pumpInbound fd tr
          let (core, rt, tr) := driveEvents prov 2048 core rt tr [InputEvent.transportReadable conn0]
          reactorRecvApp fd prov core rt tr fuel

/-- After `connected`, complete one application-data round-trip over the non-blocking path: receive the
client's record (demand-driven delivery), then `appSend` a response and flush it. -/
def reactorAppExchange (fd : UInt32) (prov : CryptoProvider)
    (core : State) (rt : RuntimeState) (tr : SocketReactor) : IO Unit := do
  let (core, rt, tr) ← reactorRecvApp fd prov core rt tr 16
  match rt.plaintextOut with
  | some b => IO.println s!"APP_RECV {b.size} bytes decrypted from client"
  | none   => IO.println "APP_RECV no plaintext delivered"
  let resp := String.toUTF8 "kroopt: hello over TLS 1.3 (nonblocking)\n"
  let (_core, _rt, tr) :=
    driveEvents prov 2048 core { rt with plaintextOut := none } tr [InputEvent.appSend conn0 resp]
  let tr ← flushOutbound fd tr
  let _ ← flushOutbound fd tr
  IO.println "APP_SENT response sealed to client"

/-- A minimal HTTP/1.1 response served over the TLS channel — the v0.3 HTTPS-termination shape (a Lean
edge server terminating TLS and answering an HTTP request). A real HTTP handler (jemmet, RFC 015) would
own this; here a fixed page stands in for it, proving the plaintext channel kroopt presents carries real
HTTP that an independent HTTP client (curl) accepts. -/
def httpResponse : ByteArray :=
  let body := String.toUTF8
    "<!doctype html><html><body><h1>kroopt</h1><p>TLS 1.3 terminated in Lean 4. Hello over HTTPS.</p></body></html>\n"
  let header := String.toUTF8 (
    "HTTP/1.1 200 OK\r\nServer: kroopt\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
      ++ toString body.size ++ "\r\nConnection: close\r\n\r\n")
  header ++ body

/-- HTTPS request/response: read the client's HTTP request over the TLS channel, send a fixed HTTP/1.1
response, then close the connection gracefully (sealed `close_notify`, RFC 8446 §6.1) so the client sees
a clean TLS shutdown rather than a truncated read. -/
def reactorHttp (fd : UInt32) (prov : CryptoProvider)
    (core : State) (rt : RuntimeState) (tr : SocketReactor) : IO Unit := do
  let (core, rt, tr) ← reactorRecvApp fd prov core rt tr 16
  match rt.plaintextOut with
  | some b => IO.println s!"HTTP_REQ {b.size} bytes received over TLS"
  | none   => IO.println "HTTP_REQ no request delivered"
  let (core, rt, tr) :=
    driveEvents prov 2048 core { rt with plaintextOut := none } tr [InputEvent.appSend conn0 httpResponse]
  let tr ← flushOutbound fd tr
  let tr ← flushOutbound fd tr
  IO.println "HTTP_RESP 200 sent over TLS"
  -- Graceful close: seal and flush an encrypted close_notify, then close the transport.
  let (_core, _rt, tr) :=
    driveEvents prov 2048 core rt tr [InputEvent.appClose conn0 .graceful]
  let tr ← flushOutbound fd tr
  let _ ← flushOutbound fd tr
  IO.println "CLOSE_NOTIFY sent (graceful)"

def serve (args : List String) : IO Unit := do
  let path := args.headD "/tmp/kroopt-tls-nb.sock"
  let mode := (args.drop 1).headD "echo"
  let ephR ← Hacl.randomBytes 32
  let srR  ← Hacl.randomBytes 32
  match ephR, srR with
  | .bytes eph, .bytes sr =>
    let liveCfg := { cfg with ephemeralPrivate := eph }
    let prov : CryptoProvider :=
      { capabilities := realCapabilities
      , submit := fun a o r =>
          match r with
          | .randomBytes _ => .ok (a, .randomBytes sr)
          | _              => RealProvider.submit liveCfg a o r }
    let s0 : State :=
      { State.initial conn0 ⟨0⟩ .sha256 with serverConfig := realServerConfig }
    let lfd ← sockListen path
    if lfd == 0xFFFFFFFF then IO.println "LISTEN FAILED"; return
    IO.println s!"kroopt TLS server (non-blocking reactor, mode={mode}) listening on {path}"
    let cfd ← sockAccept lfd
    if cfd == 0xFFFFFFFF then IO.println "ACCEPT FAILED"; sockClose lfd; return
    sockSetNonblocking cfd
    let tr0 : SocketReactor := { fdKey := { fd := cfd.toUInt64, generation := 0 } }
    let (core, rt, tr) ← reactorToConnected cfd prov s0 {} tr0 64
    match core.handshake with
    | .connected =>
        IO.println "HANDSHAKE_OK reached connected"
        if mode == "http" then reactorHttp cfd prov core rt tr
        else reactorAppExchange cfd prov core rt tr
    | _ => IO.println "HANDSHAKE_INCOMPLETE"
    sockClose cfd
    sockClose lfd
  | _, _ => IO.println "ENTROPY DRAW FAILED"

end Tests.LiveServerNb

def main (args : List String) : IO Unit := Tests.LiveServerNb.serve args
