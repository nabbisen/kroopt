import Kroopt.Conn.Transport
import Kroopt.Conn.Interpreter
import Kroopt.Conn.TlsConn
import Kroopt.Conn.Uniform
import Kroopt.Conn.Trace

/-!
# Kroopt.Conn

The runtime layer (RFC 010): the transport abstraction, the thin imperative
interpreter, and the public `TlsConn` API. The interpreter makes no protocol
decisions — `execAction` does not even take the core `State`, so it *cannot*
branch on the handshake phase; all protocol truth stays in `Kroopt.Core.step`.
This zone is impure and is never imported by the verified core.
-/
