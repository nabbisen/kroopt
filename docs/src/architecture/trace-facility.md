# No-secrets trace facility

The trace facility (RFC 036 §3) is the diagnostic backbone of the live-interop milestone.
Live TLS is where real ClientHello diversity, unknown extensions, partial I/O, and alert
differences surface, and diagnosing it needs a record of what the connection *did* — without
ever writing a secret to a log.

## Secret-freedom by construction

The facility turns the core's authorized `OutputAction` stream into `TraceEvent` values through
a pure projection, `Kroopt.Conn.traceOfAction : OutputAction → Option TraceEvent`. The single
load-bearing property is that a `TraceEvent` is secret-free *by construction*, not by a redaction
pass that could be forgotten:

- every **byte-bearing** action projects to a *length*, never the bytes — `writeTransport` and
  `emitPlaintext` become a `len`, `writeCertificate` becomes a `der-len`;
- every **secret reference** projects to a bare event or a public id — `releaseSecret` becomes a
  bare `secret-released` (the handle is dropped), and `callCrypto` becomes its *operation id* and
  *kind* only, never the request's inputs or secret handles;
- a typed error projects to its **category** only (`protocol` / `parse` / `crypto` / …), never the
  offending detail.

There is simply no `TraceEvent` constructor that can hold plaintext, ciphertext, certificate DER,
a transcript digest, or a secret handle, so `traceOfAction` cannot leak one even in principle. The
test suite (`Tests.Trace`, 19 checks) embeds a `SECRET` sentinel inside secret-bearing actions —
`emitPlaintext`, `writeTransport`, `writeCertificate`, and a secret-carrying `callCrypto` — and
asserts the rendered trace reproduces only the length/kind and never the sentinel, individually and
across a mixed action stream.

Raw attacker-controlled SNI is likewise never rendered raw: it reaches a trace only after RFC 020
redaction/hashing, which is upstream of this module.

## What a trace records

Per event: transport read/write (length), handshake-message *type* and length, the DER length of
the presented certificate, write-interest changes, crypto-op id + kind, plaintext emit/accept
lengths, the negotiated cipher suite at handshake completion, error *category*, alert
description + level, close mode, and secret-release events. `TraceEvent.render` produces one
compact, secret-free line per event; `traceActions` renders a whole action stream.

## Scope and gating

The projection and its tests landed first; the interpreter wiring followed. The interpreter's action
fold (`Conn.Interpreter.execActions`) now records one secret-free line per executed action into
`RuntimeState.trace` when `RuntimeState.traceEnabled` is set — **off by default**, matching the
production `LogPolicy` that keeps raw handshake data and transcript digests out of production logs. A
real handshake driven with the gate on produces a populated trace (crypto-op, handshake-message, and
certificate events); with the gate off it produces none and adds no overhead. The captured-client
replay bridge (RFC 036 §2) and the remaining malformed/edge capture corpus round out the live-interop
diagnostics.
