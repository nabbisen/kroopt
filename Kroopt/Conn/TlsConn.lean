import Kroopt.Conn.Interpreter

/-!
# Kroopt.Conn.TlsConn

The public connection API a consumer drives (RFC 010 §3). `TlsConn τ` is a small
handle around the core protocol `State`, the interpreter's `RuntimeState`, the
transport, and the crypto provider (RFC 010 §9). It is **generic over the
transport** `τ` (any `[Transport τ]`): the in-model `FakeTransport` for
deterministic tests, and a real I/O reactor (e.g. jemmet's iotakt-backed
`Transport`) in production. The semantics that matter:

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
  HashAlgorithm ConnId CloseMode ValidatedServerConfig AlpnProtocol CertificateChainHandle
  minProtectedRecordLen maxPlaintextFragment)
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

/-- The connection handle (RFC 010 §9), generic over the transport `τ`. Protocol
truth is `core`; the interpreter bookkeeping is `rt`; the transport `tr` and
`prov` are the boundary. The interpreter is generic over `[Transport τ]`, so the
same handle drives the in-model `FakeTransport` and a real reactor alike. -/
structure TlsConn (τ : Type) where
  core : State
  rt   : RuntimeState
  tr   : τ
  prov : CryptoProvider

namespace TlsConn

/-- Create a handshaking server connection over a supplied transport `tr0`
(RFC 010 §3), with a validated configuration (RFC 011) that drives SNI/ALPN/cert
selection. Generic over the transport: a live consumer (e.g. jemmet) passes its
real `[Transport τ]` instance here. The initial state is `start`; no application
bytes may flow yet. -/
def serverWith {τ : Type} (tr0 : τ) (conn : ConnId) (cfg : ConfigGeneration)
    (alg : HashAlgorithm) (prov : CryptoProvider)
    (config : ValidatedServerConfig := ValidatedServerConfig.baseline) : TlsConn τ :=
  { core := { State.initial conn cfg alg with serverConfig := config }
    rt   := {}
    tr   := tr0
    prov := prov }

/-- The in-model convenience constructor over the `FakeTransport` (RFC 014):
builds a fake transport from an `fd` for deterministic model/tests. Production
uses `serverWith` with a real transport. -/
def server (fd : FdKey) (conn : ConnId) (cfg : ConfigGeneration)
    (alg : HashAlgorithm) (prov : CryptoProvider)
    (config : ValidatedServerConfig := ValidatedServerConfig.baseline) : TlsConn FakeTransport :=
  serverWith { fd := fd, inbound := [] } conn cfg alg prov config

/-- Feed scripted inbound bytes (the model's stand-in for the transport delivering
a readable event with data). Model/test helper over the `FakeTransport`. -/
def feedInbound (c : TlsConn FakeTransport) (chunks : List ByteArray) : TlsConn FakeTransport :=
  { c with tr := { c.tr with inbound := c.tr.inbound ++ chunks } }

private def drive {τ : Type} [Transport τ] (c : TlsConn τ) (ev : InputEvent) : TlsConn τ :=
  -- Progress-loop fuel is the connection's configured ceiling (RFC 042 B1): the loop terminates in at
  -- most `maxProgressStepsPerCall` steps by `driveEvents`' fuel recursion.
  let fuel := c.core.serverConfig.limits.maxProgressStepsPerCall
  let (core', rt', tr') := driveEvents c.prov fuel c.core c.rt c.tr [ev]
  { c with core := core', rt := rt', tr := tr' }

/-- Read authenticated application plaintext (RFC 010 §5). Never returns bytes
before `connected` or after a terminal state. If nothing is buffered, it drives
one transport-read/decrypt cycle and retries, so a single `recv` pulls the next
record off the wire (matching the plaintext adapter's behaviour). -/
def recv {τ : Type} [Transport τ] (c : TlsConn τ) : TlsConn τ × TlsReadResult :=
  let deliver (c : TlsConn τ) : Option (TlsConn τ × TlsReadResult) :=
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
def send {τ : Type} [Transport τ] (c : TlsConn τ) (plaintext : ByteArray) : TlsConn τ × TlsWriteResult :=
  -- RFC 042 A1 — outbound-ciphertext backstop. Accept only a plaintext prefix whose sealed record keeps
  -- the interpreter-owned queue within the connection's configured `maxPendingCiphertextBytes`, so the
  -- hard invariant `rt.outbound.size ≤ cap` holds after any successful `send`. This is interpreter buffer
  -- management (the queue lives in `rt`), not a core protocol decision; the `Core.step` proofs are
  -- unaffected. Fatal alert records (`writeAlert`) are *not* gated here — they are terminal-control
  -- records, bounded to one record, and queued best-effort even when the app cap is full (RFC 042 §caveat).
  let cap := c.core.serverConfig.limits.maxPendingCiphertextBytes
  let remaining := cap - c.rt.outbound.size            -- Nat subtraction: 0 once at/over cap
  if remaining < minProtectedRecordLen then
    -- Not even a one-byte protected record fits: accept nothing, retry after flush/drain.
    (c, .wouldBlock)
  else
    -- Largest prefix whose sealed length `n + 22` fits the remaining headroom: n ≤ remaining - 22.
    let n := min (min plaintext.size maxPlaintextFragment) (remaining - 22)
    let pfx := plaintext.extract 0 n
    let c := { c with rt := { c.rt with acceptedBytes := 0 } }
    let c := drive c (.appSend c.core.connId pfx)
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
def flush {τ : Type} [Transport τ] (c : TlsConn τ) : TlsConn τ × TlsFlushResult :=
  let c := drive c (.appFlush c.core.connId)
  let (rt', tr') := drainOutbound c.rt c.tr
  let c := { c with rt := rt', tr := tr' }
  match c.rt.lastError with
  | some e => (c, .error e)
  | none =>
      if c.rt.outbound.isEmpty then (c, .flushed) else (c, .needWrite)

/-- Begin closing the connection (RFC 010 §3). After any close begins, no new
application plaintext is accepted. The completion signal is transport-agnostic:
the core reaches `.closed`, or the interpreter has driven `closeTransport`
(`rt.terminal`) which is where `Transport.closeConnection` is invoked. -/
def close {τ : Type} [Transport τ] (c : TlsConn τ) (mode : CloseMode) : TlsConn τ × TlsCloseResult :=
  let c := drive c (.appClose c.core.connId mode)
  if c.core.handshake = .closed ∨ c.rt.terminal then (c, .closed) else (c, .closeStarted)

/-- Drive the connection on a transport-readiness or timeout event (RFC 010 §3
`progress`). Returns the updated handle. -/
def progress {τ : Type} [Transport τ] (c : TlsConn τ) (ev : InputEvent) : TlsConn τ :=
  drive c ev

/-- The negotiated metadata, available after `connected` (RFC 010 §3). -/
def metadata {τ : Type} (c : TlsConn τ) : Option HandshakeInfo := c.rt.metadata

/-- The negotiated cipher suite, if the handshake completed. -/
def cipherSuite {τ : Type} (c : TlsConn τ) : Option CipherSuite := c.rt.metadata.map (·.suite)

/-- The negotiated ALPN protocol, if any (RFC 011 §5). Meaningful after
`connected`; a consumer uses it to choose its protocol handler. -/
def negotiatedAlpn {τ : Type} (c : TlsConn τ) : Option AlpnProtocol := c.core.negotiated.selectedAlpn

/-- The certificate chain selected for this connection by SNI (RFC 012 §6). -/
def selectedCert {τ : Type} (c : TlsConn τ) : Option CertificateChainHandle :=
  c.core.negotiated.selectedCert

/-- Whether the handshake has completed. -/
def isConnected {τ : Type} (c : TlsConn τ) : Bool := c.core.handshake.isConnected

/-- The number of ciphertext bytes kroopt currently owns in its outbound queue:
records the core has produced and the interpreter has queued for the transport
but not yet drained (RFC 010 §4). This is exactly the buffer `flush` drives and
reports `flushed`/`needWrite` on. A consumer (e.g. jemmet, RFC 015 §6) uses it to
bound the egress it must account for against a slow-draining peer. It is **only**
the ciphertext tier: `send` encrypts on accept, so there is no separate
accepted-but-not-encrypted plaintext backlog to report. -/
def ownedOutboundBytes {τ : Type} (c : TlsConn τ) : Nat := c.rt.outbound.size

end TlsConn

end Kroopt.Conn
