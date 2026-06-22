# HANDOFF — kroopt → iotakt team: consumer-contract review

**From:** kroopt (TLS 1.3 secure-channel library, Lean 4)
**To:** iotakt architect / team
**Date:** 2026-06-13
**Subject:** Review kroopt's use of iotakt as a non-blocking I/O consumer, before kroopt binds to the
real iotakt and before jemmet is layered on top.
**Enclosed:** this handoff, the order statements (`handoff/iotakt-review-orders.md`), and the kroopt
project (latest tagged build).

---

## 1. The one ask

kroopt is built to reach the network **only** through iotakt and to require **zero changes to iotakt**
(Requirements §2.3, §3.1.5). Everything kroopt has shipped so far runs over `SocketReactor`, an in-tree
**stand-in** that we wrote to match iotakt's contract *as we understand it from the requirements* — not
against the real iotakt. We are asking you to confirm that kroopt's consumer contract maps cleanly onto
the real iotakt API and event model, or to enumerate the deltas. The concrete output we want is the
green light (plus exact API signatures) to replace `SocketReactor` with a real `IotaktTransport`.

This review is **only** about the kroopt↔iotakt seam. It is **not** about kroopt's protocol core,
crypto, or proofs — those are validated separately (see §6).

## 2. kroopt in brief

kroopt turns a plaintext, non-blocking byte connection into an encrypted, authenticated TLS 1.3 one and
back. It sits between iotakt (which moves bytes) and jemmet (which interprets plaintext as HTTP):

```
jemmet (HTTP)  ── consumes ──▶  kroopt (TLS, this project)  ── consumes ──▶  iotakt (non-blocking I/O)
                                                                              HACL*/EverCrypt (crypto)
```

kroopt performs **no syscalls** and holds **no fd** outside iotakt's `FdKey` abstraction. It is a
sibling of jemmet, not a part of it. It is Henret-unaware: it operates on a single iotakt connection,
driven by the event loop.

## 3. The boundary under review

kroopt's architecture is a **pure verified core** (`Kroopt.Core.step`) that emits a list of
`OutputAction`s, executed by a **thin interpreter** (`Kroopt.Conn.Interpreter`) that contains no
protocol logic. The interpreter is generic over a single typeclass — `Kroopt.Conn.Transport` — which is
the entire I/O seam. iotakt plugs in as one instance of that typeclass.

### 3.1 The contract (`Kroopt/Conn/Transport.lean`)

```lean
structure FdKey where
  fd : UInt64
  generation : UInt64           -- stale events (generation mismatch) are ignored

inductive RecvOutcome | bytes (b : ByteArray) | wouldBlock | eof | error (e : TransportError)
inductive SendOutcome | sent (n : Nat) | wouldBlock | error (e : TransportError)

class Transport (τ : Type) where
  fd              : τ → FdKey
  recv            : τ → FdKey → Nat → RecvOutcome × τ      -- non-blocking read; readiness is a hint
  send            : τ → FdKey → ByteArray → SendOutcome × τ -- non-blocking write; partial accept allowed
  enableWrite     : τ → FdKey → τ
  disableWrite    : τ → FdKey → τ
  closeConnection : τ → FdKey → τ
```

This is the full set of capabilities kroopt requires (External Design §10.1). If kroopt needs anything
beyond these generic primitives — in particular anything TLS-aware — the boundary is violated and we
need to know.

### 3.2 How I/O actually happens

The `Transport` methods above are **pure** (no `IO`). kroopt's effects flow through the action/event
loop, not through monadic transport calls:

- The core *pulls* reads: when it needs bytes it emits `OutputAction.readTransport`; the interpreter
  runs `Transport.recv` and feeds the result back as `InputEvent.transportBytes` (or no event on
  `wouldBlock`, or `transportEof` on EOF).
- The core *pushes* writes: `writeTransport` / `writeHandshake` / `writeCertificate` are framed and sent
  via `Transport.send`; partial sends keep the unsent suffix and the core arms write interest.
- Readiness hints enter as `InputEvent.transportReadable` / `transportWritable`; the core turns
  `transportReadable` into a `readTransport` action (it does not assume data is present).
- Write interest: `OutputAction.enableWriteInterest` / `disableWriteInterest` → `Transport.enableWrite`
  / `disableWrite`.
- Close: `OutputAction.closeTransport mode` → `Transport.closeConnection`.

Because the typeclass is pure, the **real iotakt adapter is an IO reactor that wraps it**: it performs
iotakt's actual `recv`/`send` in `IO`, stages bytes into the `Transport` state, runs the pure
interpreter (which pulls/pushes through that state), and drains the staged outbound via iotakt's `send`.
`SocketReactor` (`Tests/LiveServerNb.lean`) does exactly this over raw non-blocking sockets and is the
template for `IotaktTransport`.

### 3.3 The core's event/action vocabulary (for reference)

Inbound `InputEvent`s relevant to transport: `transportBytes`, `transportReadable`, `transportWritable`,
`transportEof`. Outbound `OutputAction`s relevant to transport: `readTransport`, `writeTransport`,
`writeHandshake`, `writeCertificate`, `enableWriteInterest`, `disableWriteInterest`, `closeTransport`.
(The rest — `callCrypto`, `emitPlaintext`, `appSend`, `appClose`, etc. — are crypto- or
application-facing and do not touch iotakt.)

## 4. How we believe this maps onto iotakt (please confirm/correct)

From Requirements §2.3, which states this is "exactly iotakt's RFC 041 handoff":

| kroopt concept | iotakt (as we understand it) |
|---|---|
| `readTransport` → `Transport.recv` returning `wouldBlock` (TLS `WANT_READ`) | `recv(fd)` → would-block; wait for `IoEvent.readable` |
| `enableWriteInterest` + retry on `transportWritable` (TLS `WANT_WRITE`) | `EventLoop.enableWrite` + `IoEvent.writable` |
| `FdKey { fd, generation }`, stale-event filtering | iotakt's generation-protected `FdKey` |
| `closeTransport` → `Transport.closeConnection` | `EventLoop.closeConnection` (also cancels the owning Henret task) |
| `transportEof` (distinct from `error`) | peer-closed signal, distinct from transport error |
| `SendOutcome.sent n` (partial) + keep suffix | iotakt `WriteResult` partial-accept / `WriteBuffer` pattern |
| kroopt owns reassembly + pending-ciphertext buffers | iotakt owns fd lifecycle; no double buffering |

If any row is wrong, that is the most important thing for us to learn.

## 5. The specific assumptions we most want eyes on

1. **Control ownership.** `SocketReactor` owns its own `poll` loop. The real integration should be the
   inverse: iotakt owns the event loop and invokes kroopt per `IoEvent`, with kroopt running its bounded
   progress loop to a stable boundary (need-read / need-write / plaintext-available / handshake-complete
   / terminal) and then yielding. kroopt's interpreter is already event-shaped for this. Please confirm
   the integration is "iotakt calls kroopt on each readiness event," not "kroopt drives iotakt."
2. **Pure-Transport / IO-reactor pattern.** Confirm the staging pattern in §3.2 composes with iotakt's
   real `recv`/`send` and does not fight an iotakt-side buffering or ownership protocol.
3. **`FdKey` identity & staleness.** Confirm field types and generation semantics match, and that
   kroopt may rely on iotakt to filter stale-generation events.
4. **Readiness is a hint.** Confirm `recv`/`send` may report would-block after a readiness event and
   that the `enableWrite` → `writable` re-arm cycle behaves as assumed.
5. **Partial writes.** Confirm iotakt exposes a partial-accept byte count and that kroopt's
   keep-the-suffix + re-arm-write-interest strategy is the intended pattern.
6. **Close ordering & Henret.** kroopt's graceful close flushes a sealed `close_notify`, *then* calls
   `closeConnection`. Confirm this ordering and the Henret-task-cancellation side effect are correct,
   and that abortive/fatal closes route the same way.
7. **EOF vs error.** Confirm iotakt distinguishes peer-close (EOF) from transport error, so kroopt can
   treat EOF-before-`close_notify` as truncation (a failure) rather than a clean close.
8. **Buffer ownership.** Confirm there is no conflict between kroopt's owned buffers (inbound record
   reassembly, outbound pending ciphertext, one-record plaintext) and iotakt's WriteBuffer.
9. **Zero-changes litmus.** Confirm kroopt requires only the §3.1 generic primitives and **no
   TLS-specific iotakt API**. Any required iotakt change is a boundary violation we must redesign around.

## 6. What is already validated (so you can scope the review tightly)

Over the `SocketReactor` stand-in, kroopt completes, against **independent** implementations:

- a full TLS 1.3 handshake (ChaCha20-Poly1305, X25519, Ed25519) with **OpenSSL `s_client`** and
  **Python `ssl`** (`scripts/tls-interop.sh`);
- bidirectional application-data, in both a blocking driver and the non-blocking readiness reactor;
- a real **HTTPS** request: **curl** and Python receive `HTTP/1.1 200 OK` and a graceful, authenticated
  `close_notify` (`scripts/https-e2e.sh`).

The protocol core is machine-checked (no `sorry`/`axiom`/`unsafe` in the strict zones; 94 audited
theorems) and the crypto FFI is sanitizer- and known-answer-tested. None of that is in scope here — it
only tells you the seam is the **last** unvalidated assumption.

## 7. Where to look

- `Kroopt/Conn/Transport.lean` — the contract (the typeclass, `FdKey`, outcomes) and the in-model
  `FakeTransport` instance.
- `Tests/LiveServerNb.lean` — `SocketReactor`: the non-blocking, readiness-driven reactor that is the
  template for the real `IotaktTransport`.
- `Kroopt/Conn/Interpreter.lean` — the action→I/O mapping (`readTransport`/`writeTransport`/
  `enableWriteInterest`/`closeTransport` → `Transport` calls). No protocol logic lives here.
- `Kroopt/Core/Event.lean`, `Kroopt/Core/Action.lean` — the event/action vocabulary.
- `scripts/tls-interop.sh`, `scripts/https-e2e.sh` — run these to see the seam exercised end to end.
- `rfcs/proposed/010-tlsconn-api-nonblocking-interpreter.md` — the TlsConn/interpreter RFC (the seam's
  design rationale; still `proposed`, not frozen).
- Requirements §2.3 and External Design §10 — kroopt's stated iotakt relationship.

The order statements in `handoff/iotakt-review-orders.md` enumerate exactly what we ask you to confirm
or return.
