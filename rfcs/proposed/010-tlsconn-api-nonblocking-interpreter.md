# RFC 010 — TlsConn API and Non-Blocking iotakt Interpreter

**Project.** kroopt  
**Status.** Proposed (ACTIVE — unfrozen after the RFC 037 M37 native-hardening band landed at 0.48.0-dev; the verified core + production interpreter now drive a real handshake, so the real-socket I/O driver and live interop are in scope)  
**Type.** Implementation RFC  
**Target milestone.** M7  
**Depends on.** RFC 002, RFC 004, RFC 008  
**Touches.** `Kroopt/Conn/{TlsConn,Interpreter}.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's public connection API and the interpreter that executes core actions over iotakt and the crypto provider. `TlsConn` is the API jemmet will depend on. Its semantics must be precise, especially for writes: `wrote n` means plaintext accepted into kroopt ownership, not ciphertext delivered to the peer.

## 2. Goals

- Define `TlsConn` public API.
- Map core actions to iotakt operations.
- Define write, flush, progress, and close semantics.
- Enforce resource budgets and bounded queues.
- Prevent stale event/result confusion.

## 3. Public API sketch

```lean
namespace Kroopt.Conn

structure TlsConn

inductive TlsReadResult where
  | bytes (b : ByteArray)
  | wouldBlock
  | eof
  | closed
  | error (e : TlsError)

inductive TlsWriteResult where
  | wrote (n : Nat)
  | wouldBlock
  | closed
  | error (e : TlsError)

inductive TlsFlushResult where
  | flushed
  | pending
  | wouldBlock
  | closed
  | error (e : TlsError)

def create : Iotakt.FdKey -> ServerConfig -> IO (Except TlsError TlsConn)
def progress : TlsConn -> IoEvent -> IO (TlsConn × ProgressResult)
def recv : TlsConn -> IO (TlsConn × TlsReadResult)
def send : TlsConn -> ByteArray -> IO (TlsConn × TlsWriteResult)
def flush : TlsConn -> IO (TlsConn × TlsFlushResult)
def close : TlsConn -> CloseIntent -> IO (TlsConn × CloseResult)
def state : TlsConn -> TlsConnStateView
def negotiatedAlpn : TlsConn -> Option ALPNProtocol
```

The exact functional/IO style may adapt to the iotakt idioms, but the semantics below are mandatory.

## 4. Write semantics

- `wrote n` means kroopt has taken ownership of exactly `n` plaintext bytes.
- `wouldBlock` means zero plaintext bytes were consumed.
- `wrote n` does not mean ciphertext reached the peer.
- Accepted plaintext may be encrypted into pending ciphertext and flushed later.
- jemmet must call `flush` or rely on event-loop `progress` to drive pending writes.
- If encryption or transport later fails, the connection fails; jemmet must not resend accepted bytes unless its own application protocol chooses to retry at a higher layer.

## 5. Read semantics

- `bytes b` returns authenticated plaintext only.
- `wouldBlock` means no authenticated plaintext is currently available.
- `eof` is returned only after transport EOF is interpreted according to close policy.
- `closed` means no future plaintext will be produced.
- `error e` is typed and redacted.

## 6. Interpreter action mapping

| OutputAction | Interpreter behavior |
|---|---|
| `readTransport` | call iotakt recv; feed bytes/wouldBlock/eof back to core |
| `writeTransport b` | append to bounded pending transport queue; attempt iotakt send |
| `enableWriteInterest` | call iotakt EventLoop.enableWrite |
| `disableWriteInterest` | disable when queue empty |
| `callCrypto` | submit to provider; feed correlated result back |
| `emitPlaintext` | store one bounded plaintext record for `recv` |
| `reportHandshakeComplete` | update public state view and ALPN |
| `failWithAlert` | queue alert if possible, then fail terminally |
| `closeTransport` | call iotakt closeConnection |

The interpreter may contain retry loops only within configured progress budgets.

## 7. Resource budgets

`TlsConn` enforces:

- maximum inbound record buffer bytes;
- maximum pending ciphertext bytes;
- maximum pending ciphertext records;
- maximum single app send acceptance size;
- maximum progress loop iterations per call;
- handshake timeout;
- idle timeout if configured;
- maximum pending crypto operations.

Budget exhaustion becomes a typed TLS error and usually a fatal alert.

## 8. Stale event defense

Each `TlsConn` carries:

- iotakt `FdKey` generation;
- kroopt `ConnId` generation;
- config generation;
- operation ids for pending crypto;
- state generation incremented on terminal transition.

Transport events or crypto results that do not match generation metadata are rejected or ignored according to deterministic policy.

## 9. Internal design

`TlsConn` should be a small handle around an internal state record:

```lean
structure TlsConnInner where
  fd : Iotakt.FdKey
  core : Kroopt.Core.State
  runtime : RuntimeState
  config : ServerConfigRef
  provider : CryptoProviderRef
```

`RuntimeState` contains pending transport bytes, provider handles, and event-loop integration state. Protocol state remains in `core`.

## 10. Security considerations

- Never expose unauthenticated bytes through `recv`.
- Never accept application plaintext before connected.
- Never hide unbounded ciphertext queues behind `send`.
- Never log plaintext or secrets on write failure.
- Never spin indefinitely on repeated wouldBlock.

## 11. Tests

- `send` wouldBlock consumes zero bytes.
- `send` wrote means bytes are not accepted twice.
- `flush` drives pending ciphertext.
- Partial iotakt writes preserve byte ordering.
- Repeated wouldBlock stops at progress budget.
- Stale fd generation event is ignored/rejected.
- Stale crypto result is rejected.

## 12. Acceptance criteria

- Public API is documented with consumption semantics.
- Interpreter executes action variants without protocol branching.
- iotakt integration requires no iotakt source changes.
- Bounded queues and progress budgets are implemented.
- Tests cover partial writes, wouldBlock, and stale events.

## Progress

- **Real-socket driver (first increment, 0.48.0-dev+).** `Tests/SocketDriver.lean` drives the verified core +
  production interpreter over a real AF_UNIX socket: a ClientHello arrives from the wire, the core processes it
  with the real HACL* provider, and the sealed server flight is written back to the wire (peer confirms record framing). A second socketpair
  completes the full round-trip to `connected`: the peer puts a valid client Finished on the wire, the core
  opens it, `verifyFinished` checks the MAC, and the handshake reaches `connected` over real kernel I/O. The interpreter stays pure — the `driveOverSocket` loop owns the
  syscalls and flushes only core-authorised bytes (§6). Remaining: the full round-trip to `connected` (client
  Finished from the wire), non-blocking/readiness-driven progress, and live interop (RFC 026) / jemmet E2E (RFC 015).
