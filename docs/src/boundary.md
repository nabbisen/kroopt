# Boundary and non-goals

kroopt owns the TLS 1.3 secure channel and nothing else (RFC 001).

* **iotakt** owns sockets, readiness, and byte transport. kroopt never opens,
  closes, or polls a file descriptor directly; it asks the interpreter to read,
  write, or close through iotakt. No change to iotakt is permitted for kroopt's
  convenience (RFC 001 §1).
* **kroopt** owns the record layer, handshake, key schedule, alerts, and the
  secure-channel API. Its verified core decides *what* happens; the interpreter
  decides *how* to carry it out.
* **jemmet** owns HTTP semantics and ALPN policy. kroopt surfaces the negotiated
  ALPN protocol but never interprets it (RFC 011).

## The core/interpreter contract

The core is a pure function `step : State → InputEvent → Except TlsError
(State × List OutputAction)`. Everything that crosses the boundary does so as an
explicit `InputEvent` (in) or `OutputAction` (out). The interpreter may not
re-implement any protocol transition (RFC 002 §5). This is enforced from M0 by
the module-dependency gate (`scripts/check-deps.sh`): the verified core may not
import the interpreter, the crypto provider, the native shim, or iotakt.

## Non-goals (deferred, RFC 016)

Client role, mutual TLS, peer X.509 path validation, session tickets / 0-RTT,
HelloRetryRequest, post-handshake KeyUpdate, TLS 1.2, QUIC, and DTLS are out of
scope for the initial releases and each requires its own RFC before adoption.
