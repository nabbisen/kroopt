# TlsConn API and the interpreter

M7 adds the runtime layer (RFC 010): the public `TlsConn` connection API jemmet
depends on, and the thin imperative interpreter that executes the core's actions
over the transport and the crypto provider.

## No protocol decisions in the interpreter

The central discipline (RFC 002 §5, RFC 010 §12) is that the interpreter
re-implements **no** protocol logic — all protocol truth stays in
`Kroopt.Core.step`. In kroopt this is enforced structurally rather than by
convention: `execAction`, the function that runs one `OutputAction`, does not
even take the core `State` as an argument. It dispatches on the action *variant*
alone — read, write, enable/disable write interest, call crypto, emit/accept
plaintext, report, fail, close, release — and so it *cannot* branch on the
handshake phase, choose a suite, or derive a sequence number even by accident.
The drive loop holds the core `State` only to call `step`; the action executor
never sees it.

This makes the proof/runtime correspondence a runtime artifact: every safety
property proved over `step` (no early plaintext, no unauthenticated plaintext,
sequence/key discipline, operation-id correlation) governs the running connection
unchanged, because the running connection's protocol decisions *are* `step`.

## Write semantics

`send` returns `wrote n` meaning kroopt took ownership of exactly `n` plaintext
bytes — **not** that ciphertext reached the peer. `wouldBlock` consumes zero, so
the caller retries the same bytes. Accepted plaintext is encrypted into a bounded
pending-ciphertext queue and pushed toward the transport by `flush` or by driving
the connection on a writable event. Partial transport writes remove only the sent
prefix, preserving byte order; a `wouldBlock` leaves the queue intact.

## Read and close semantics

`recv` returns authenticated application plaintext only, and only after
`connected`; otherwise `wouldBlock`, `eof` (a clean close), `closed`, or a typed
`error`. The decrypted-plaintext path is: an `aeadOpened` result buffers one
record into the core, and `recv` (an `appRecvRequested` event) is what emits it to
the caller — so plaintext crosses the boundary through a single connected-gated
site. `close` begins the close handshake; after it, no new application plaintext
is accepted.

## Bounded, stale-safe, transport-neutral

The drive loop is fuel-bounded, so it can never spin on repeated `wouldBlock`
(RFC 010 §10). Stale events and results are rejected by generation/operation-id
metadata — a crypto result whose id is not outstanding is dropped (the proved
`stale_crypto_result_rejected`). kroopt requires only generic non-blocking
transport capabilities (`recv`/`send`/`enableWrite`/`closeConnection`, a
generation-protected `FdKey`) — **no TLS-specific transport API**. For this
milestone the transport is a pure, deterministic fake, which makes the whole
interpreter testable without sockets; the real iotakt binding is a thin adapter
that lifts the identical action-mapping into iotakt's IO calls and is wired in at
v0.3 integration.
