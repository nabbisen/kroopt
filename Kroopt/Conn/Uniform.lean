import Kroopt.Conn.TlsConn
import Kroopt.Conn.Metrics

/-!
# Kroopt.Conn.Uniform

The consumer-facing integration surface (RFC 015). A consumer (such as an HTTP
server) must not need a separate HTTPS handler path: it consumes one **uniform
plaintext connection abstraction** whose implementation is either a plaintext
connection or a kroopt `TlsConn`, chosen by listener wiring (RFC 015 §3, §4).
Whichever it is, the consumer runs a single handler over the same
`recv`/`send`/`flush`/`close` shape and reads the negotiated ALPN to pick its
protocol handler.

This module defines that abstraction (`PlainConn`), a plaintext adapter
(`PlaintextConn`) for the `:80` path, the `TlsConn` instance for the `:443`
path, a redacted error view for diagnostics, and bounded metrics. A real
transport binding and real interop (curl / OpenSSL) are the deferred v0.3
binding; the abstraction and adapters here are exercised against the fakes.
-/

namespace Kroopt.Conn

open Kroopt (TlsError AlertDescription ProtocolError ParseError CryptoError
  ConfigError ResourceLimitError TransportError)
open Kroopt.Core (AlpnProtocol CloseMode ConfigGeneration)

/-- The uniform connection shape a consumer depends on (RFC 015 §4). Both a
plaintext connection and a TLS `TlsConn` implement it, so the consumer runs one
path. The operations thread the connection state purely (a real transport
binding lifts the identical shape into IO). -/
class PlainConn (σ : Type) where
  recv : σ → σ × TlsReadResult
  send : σ → ByteArray → σ × TlsWriteResult
  flush : σ → σ × TlsFlushResult
  close : σ → CloseMode → σ × TlsCloseResult
  /-- The negotiated ALPN protocol, if any. `none` for plaintext. -/
  negotiatedProtocol : σ → Option AlpnProtocol
  /-- Whether application bytes may flow (always true for plaintext; true after
  the handshake for TLS). -/
  isConnected : σ → Bool

/-- `TlsConn` is the `:443` implementation of the uniform shape (RFC 015 §4). The
ops are exactly the public `TlsConn` API — no new behaviour. -/
instance : PlainConn TlsConn where
  recv c := c.recv
  send c b := c.send b
  flush c := c.flush
  close c m := c.close m
  negotiatedProtocol c := c.negotiatedAlpn
  isConnected c := c.isConnected

/-- A plaintext (non-TLS) connection adapter — the `:80` path (RFC 015 §3). No TLS,
no handshake: application bytes flow immediately and no ALPN is negotiated. -/
structure PlaintextConn where
  inbound  : List ByteArray
  outbound : ByteArray := ByteArray.mk #[]
  closed   : Bool := false
  deriving Inhabited

instance : PlainConn PlaintextConn where
  recv c :=
    match c.inbound with
    | chunk :: rest => ({ c with inbound := rest }, .bytes chunk)
    | [] => if c.closed then (c, .closed) else (c, .wouldBlock)
  send c b :=
    if c.closed then (c, .closed)
    else ({ c with outbound := c.outbound ++ b }, .wrote b.size)
  flush c := (c, .flushed)
  close c _ := ({ c with closed := true }, .closed)
  negotiatedProtocol _ := none
  isConnected c := !c.closed

/-! ## Redacted error view (RFC 015 §6) -/

/-- The redacted, typed failure view a consumer may log (RFC 015 §6, §9). It carries a
category, the alert sent/received if any, and the config generation — and **by
construction** no secrets, no decrypted plaintext, and no raw attacker-controlled
bytes (there are simply no such fields). A raw SNI is reduced to its length. -/
structure TlsErrorView where
  category      : ErrorCategory
  alert         : Option AlertDescription
  configGen     : ConfigGeneration
  sniPreviewLen : Option Nat
  deriving Repr, Inhabited

/-- Build the redacted view from a connection's state and error. -/
def redactError (c : TlsConn) (e : TlsError) : TlsErrorView :=
  { category := categoryOf e
    alert := match c.core.closeState with
             | .fatalSent a => some a
             | .fatalReceived a => some a
             | _ => none
    configGen := c.core.configGen
    sniPreviewLen := c.core.negotiated.selectedSni.map (·.size) }

end Kroopt.Conn
