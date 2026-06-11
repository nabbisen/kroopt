import Kroopt.Core.Id
import Kroopt.Core.Common
import Kroopt.Core.Crypto

/-!
# Kroopt.Core.Event

The input events that drive the pure core (RFC 002 §3, requirements §7.1).

Readiness events (`transportReadable`/`transportWritable`) are hints, not data:
the interpreter turns a readiness hint into an actual transport read and then
feeds `transportBytes` (or no event) back to the core (RFC 002 §3, RFC 010 §5).
Application demand (`appSend`/`appRecvRequested`) is explicit so the core
controls exactly when plaintext may be emitted or accepted.

No `Repr` is derived: events carry `ByteArray` (attacker bytes / plaintext) and
`CryptoResult` (secret-bearing), which must not be printable (RFC 018).
-/

namespace Kroopt.Core

/-- Events entering `step`. Every external happening that can affect TLS state
arrives as one of these (RFC 002 §5 rule 1). -/
inductive InputEvent where
  /-- Bytes actually read from the transport for this connection. -/
  | transportBytes (conn : ConnId) (b : ByteArray)
  /-- iotakt signalled the fd may be readable (a hint). -/
  | transportReadable (conn : ConnId)
  /-- iotakt signalled the fd may be writable (a hint). -/
  | transportWritable (conn : ConnId)
  /-- Peer end-of-stream on the transport. -/
  | transportEof (conn : ConnId)
  /-- A previously requested crypto operation completed. -/
  | cryptoResult (conn : ConnId) (op : OperationId) (r : CryptoResult)
  /-- The application (jemmet) wants to send plaintext. -/
  | appSend (conn : ConnId) (b : ByteArray)
  /-- The application requested available plaintext. -/
  | appRecvRequested (conn : ConnId)
  /-- The application asked to drive pending output toward the transport. -/
  | appFlush (conn : ConnId)
  /-- The application asked to close, with a chosen mode. -/
  | appClose (conn : ConnId) (mode : CloseMode)
  /-- A handshake/idle/close timeout or budget tick fired. -/
  | timeout (conn : ConnId) (kind : TimeoutKind)

namespace InputEvent

/-- The connection an event concerns (used for generation checks at the boundary). -/
def conn : InputEvent → ConnId
  | transportBytes c _   => c
  | transportReadable c  => c
  | transportWritable c  => c
  | transportEof c       => c
  | cryptoResult c _ _   => c
  | appSend c _          => c
  | appRecvRequested c   => c
  | appFlush c           => c
  | appClose c _         => c
  | timeout c _          => c

end InputEvent

end Kroopt.Core
