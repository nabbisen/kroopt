import Kroopt.Conn.Interpreter

/-!
# Kroopt.Conn.TlsConn

The public connection API jemmet depends on (RFC 010 §3). `TlsConn` is a small
handle around the core protocol `State`, the interpreter's `RuntimeState`, the
transport, and the crypto provider (RFC 010 §9). The semantics that matter:

* `recv` returns **authenticated plaintext only**, and only after `connected`;
* `send` returns `wrote n` meaning kroopt **took ownership of `n` plaintext
  bytes** — *not* that ciphertext reached the peer (RFC 010 §4); `wouldBlock`
  consumes **zero**;
* `flush` drives pending ciphertext toward the transport;
* `close` begins the close handshake.

Every method drives the core with a single external event through the
fuel-bounded interpreter and then reads the runtime view. No method makes a
protocol decision — they marshal events in and results out.
-/

namespace Kroopt.Conn

open Kroopt (TlsError)
open Kroopt.Core (State InputEvent HandshakeInfo CipherSuite ConfigGeneration
  HashAlgorithm ConnId CloseMode ValidatedServerConfig AlpnProtocol CertificateChainHandle)
open Kroopt.Crypto (CryptoProvider)

inductive TlsReadResult where
  | bytes (b : ByteArray)
  | wouldBlock
  | eof
  | closed
  | error (e : TlsError)
  deriving Inhabited

inductive TlsWriteResult where
  | wrote (n : Nat)
  | wouldBlock
  | closed
  | error (e : TlsError)
  deriving Inhabited

inductive TlsFlushResult where
  | flushed
  | needWrite
  | closed
  | error (e : TlsError)
  deriving Inhabited

inductive TlsCloseResult where
  | closeStarted
  | closed
  | error (e : TlsError)
  deriving Inhabited

/-- The connection handle (RFC 010 §9). Protocol truth is `core`; the interpreter
bookkeeping is `rt`; the transport and provider are the boundary. -/
structure TlsConn where
  core : State
  rt   : RuntimeState
  tr   : FakeTransport
  prov : CryptoProvider

namespace TlsConn

/-- Create a handshaking server connection over an accepted fd (RFC 010 §3),
with a validated configuration (RFC 011) that drives SNI/ALPN/cert selection.
The initial state is `start`; no application bytes may flow yet. -/
def server (fd : FdKey) (conn : ConnId) (cfg : ConfigGeneration)
    (alg : HashAlgorithm) (prov : CryptoProvider)
    (config : ValidatedServerConfig := default) : TlsConn :=
  { core := { State.initial conn cfg alg with serverConfig := config }
    rt   := {}
    tr   := { fd := fd, inbound := [] }
    prov := prov }

/-- Feed scripted inbound bytes (the model's stand-in for iotakt delivering a
readable event with data). -/
def feedInbound (c : TlsConn) (chunks : List ByteArray) : TlsConn :=
  { c with tr := { c.tr with inbound := c.tr.inbound ++ chunks } }

private def drive (c : TlsConn) (ev : InputEvent) : TlsConn :=
  let (core', rt', tr') := driveEvents c.prov progressBudget c.core c.rt c.tr [ev]
  { c with core := core', rt := rt', tr := tr' }

/-- Read authenticated application plaintext (RFC 010 §5). Never returns bytes
before `connected` or after a terminal state. If nothing is buffered, it drives
one transport-read/decrypt cycle and retries, so a single `recv` pulls the next
record off the wire (matching the plaintext adapter's behaviour). -/
def recv (c : TlsConn) : TlsConn × TlsReadResult :=
  let deliver (c : TlsConn) : Option (TlsConn × TlsReadResult) :=
    match c.rt.plaintextOut with
    | some b => some ({ c with rt := { c.rt with plaintextOut := none } }, .bytes b)
    | none => none
  let c := drive c (.appRecvRequested c.core.connId)
  match deliver c with
  | some r => r
  | none =>
      if c.core.handshake.isTerminal then
        match c.rt.lastError with
        | some e => (c, .error e)
        | none   => (c, .closed)
      else
        -- Pull and decrypt the next record, then retry delivery once.
        let c := drive c (.transportReadable c.core.connId)
        let c := drive c (.appRecvRequested c.core.connId)
        match deliver c with
        | some r => r
        | none =>
            if c.core.handshake.isTerminal then
              match c.rt.lastError with
              | some e => (c, .error e)
              | none   => (c, .closed)
            else (c, .wouldBlock)

/-- Accept application plaintext for encryption and transmission (RFC 010 §4).
`wrote n` = kroopt took ownership of `n` plaintext bytes; `wouldBlock` = zero
consumed (the caller retries the same bytes). -/
def send (c : TlsConn) (plaintext : ByteArray) : TlsConn × TlsWriteResult :=
  let c := { c with rt := { c.rt with acceptedBytes := 0 } }
  let c := drive c (.appSend c.core.connId plaintext)
  if c.core.handshake.isTerminal then
    match c.rt.lastError with
    | some e => (c, .error e)
    | none   => (c, .closed)
  else if c.rt.acceptedBytes > 0 then
    (c, .wrote c.rt.acceptedBytes)
  else
    (c, .wouldBlock)

/-- Drive pending ciphertext toward the transport (RFC 010 §4). `flushed` means
kroopt's outbound queue is empty (not that the peer processed the data). -/
def flush (c : TlsConn) : TlsConn × TlsFlushResult :=
  let c := drive c (.appFlush c.core.connId)
  let (rt', tr') := drainOutbound c.rt c.tr
  let c := { c with rt := rt', tr := tr' }
  match c.rt.lastError with
  | some e => (c, .error e)
  | none =>
      if c.rt.outbound.isEmpty then (c, .flushed) else (c, .needWrite)

/-- Begin closing the connection (RFC 010 §3). After any close begins, no new
application plaintext is accepted. -/
def close (c : TlsConn) (mode : CloseMode) : TlsConn × TlsCloseResult :=
  let c := drive c (.appClose c.core.connId mode)
  if c.tr.closed ∨ c.core.handshake = .closed then (c, .closed) else (c, .closeStarted)

/-- Drive the connection on a transport-readiness or timeout event (RFC 010 §3
`progress`). Returns the updated handle. -/
def progress (c : TlsConn) (ev : InputEvent) : TlsConn :=
  drive c ev

/-- The negotiated metadata, available after `connected` (RFC 010 §3). -/
def metadata (c : TlsConn) : Option HandshakeInfo := c.rt.metadata

/-- The negotiated cipher suite, if the handshake completed. -/
def cipherSuite (c : TlsConn) : Option CipherSuite := c.rt.metadata.map (·.suite)

/-- The negotiated ALPN protocol, if any (RFC 011 §5). Meaningful after
`connected`; jemmet uses it to choose its protocol handler. -/
def negotiatedAlpn (c : TlsConn) : Option AlpnProtocol := c.core.negotiated.selectedAlpn

/-- The certificate chain selected for this connection by SNI (RFC 012 §6). -/
def selectedCert (c : TlsConn) : Option CertificateChainHandle :=
  c.core.negotiated.selectedCert

/-- Whether the handshake has completed. -/
def isConnected (c : TlsConn) : Bool := c.core.handshake.isConnected

end TlsConn

end Kroopt.Conn
