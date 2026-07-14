# RFC 055 — TLS Accounting, Sizing, and Progress Contract

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking downstream integration/API fix  
**Target milestone.** AR-I integration enabler, before AR1 protocol changes  
**Requires completion of.** [RFC 010](../done/010-tlsconn-api-nonblocking-interpreter.md), [RFC 019](../done/019-resource-budgets-backpressure-and-dos-defense.md), [RFC 042](../done/042-resource-limit-enforcement.md)  
**Coordinates with.** [RFC 047](047-monotonic-deadlines-and-timeout-enforcement.md), [RFC 048](048-validated-construction-and-protected-epoch-fail-closed.md), [RFC 050](050-bounded-certificate-chain-presentation.md), [RFC 052](052-jemmet-iotakt-production-path-acceptance.md)  
**Touches.** `TlsConn` accounting/admission API, validated egress bounds, transport-progress contract, connection/iotakt tests and handoff  

## Request and finding

Jemmet's M3 adapter needs to enforce aggregate ingress and egress bounds without projecting kroopt private
state or copying TLS constants. Review found that the request is valid but not accessor-only:

- retained inbound data exists in record/reassembly, authenticated-plaintext, transcript, and parsed
  handshake representations;
- `TlsConn.send` duplicates the protected-record overhead literal instead of consuming the public sizing
  function, and zero-length input can queue a record before returning `wouldBlock`;
- runtime `writeInterest` is not a usable readiness contract: the core does not emit its actions and a
  writable event alone does not drain the interpreter queue;
- handshake and terminal-control output bypass application admission and need separate finite reserves;
- kroopt-to-transport transfer is not peer delivery, while transport-owned staging/discard remains the
  adapter's accounting responsibility.

## Decision

### Retained inbound charge

`TlsConn.inboundOwnership` returns a structured conservative **retained-byte charge** based on live
`ByteArray.size` values, not allocated capacity and not lifetime-total traffic. It separates record
reassembly, handshake reassembly, authenticated plaintext, and retained inbound handshake representations;
`ownedInboundBytes` is their sum. Duplicate retained representations are charged separately, so the value
upper-bounds logical byte ownership rather than deduplicating shared origins.

When `recv` returns `.bytes b`, the returned connection no longer owns that authenticated-plaintext buffer;
jemmet owns `b` and any `plainCarry` suffix. Other retained handshake state may keep the total nonzero.
Terminal state reports retained buffers truthfully until the connection value is released or explicit cleanup
removes them.

### Protected-record sizing and send admission

One suite-aware API owns AEAD tag/record expansion and plaintext-budget fitting. All currently supported
suites use a 16-byte tag, but callers pass the suite so a future provider cannot silently change expansion.
`TlsConn.send` consumes the same function; no private `22` literal remains. Connected zero-length input is a
no-op returning `.wrote 0` with unchanged state. `wouldBlock` consumes zero and changes no ownership.

### Flight and terminal reserves

A validated configuration exposes a conservative maximum server-flight wire-byte reserve covering the
plaintext ServerHello plus every protected server-flight record that can be successfully framed before peer
input. The initial implementation uses protocol record maxima, so it remains safe even when a configuration
would fail framing; RFC 050 must update the bound and its covering test when certificate fragmentation adds
records.

The terminal-control reserve is the maximum of a plaintext fatal alert, protected fatal alert, and protected
`close_notify`. It is separate from `maxPendingCiphertextBytes`; aggregate egress may temporarily reach the
application cap plus this one-record reserve.

### Writable progress and conservation

Jemmet keeps `needsWrite == aggregate owned ciphertext > 0`. It drains its own staging on writable readiness,
then calls `TlsConn.flush` to transfer more kroopt-owned ciphertext. `RuntimeState.writeInterest` is internal
and not a public readiness signal. Immediate work/read/timer classification is separate and may expand under
RFC 047.

Transfer from `rt.outbound` to transport-owned staging preserves aggregate ownership. Partial acceptance
retains the ordered kroopt suffix; `wouldBlock` transfers zero. Only real socket acceptance decrements the
aggregate. Kroopt does not silently discard `rt.outbound` on terminalization. A concrete adapter that drops
its own staging on close must record that amount as an explicit adapter-owned discard.

## Work breakdown

1. Add structured inbound ownership and scalar total accessors.
2. Add suite-aware protected-record sizing and maximum-plaintext-for-budget functions.
3. Make `TlsConn.send` use those functions and define zero-length/non-mutation behavior.
4. Add validated server-flight and terminal-control reserves with derivation comments.
5. Freeze writable-progress and transfer/discard conservation wording.
6. Add deterministic tests for every boundary and update the iotakt translation contract.
7. Publish a versioned response with exact release provenance for jemmet to pin.

## Acceptance criteria

1. Inbound charges cover partial records, handshake reassembly, buffered/delivered plaintext, retained
   inbound handshake state, and terminal states without using cumulative traffic counters.
2. Record sizing equals actual application ciphertext for every supported suite at plaintext sizes 0, 1,
   maximum, and over-maximum.
3. Connected zero-length send is a state-preserving `.wrote 0`; every `wouldBlock` path is ownership-neutral.
4. The server-flight bound covers the largest successfully emitted current flight; the terminal reserve
   covers plaintext/protected fatal alert and protected `close_notify`.
5. Tests preserve aggregate ownership through partial transfer, `wouldBlock`, flush cycles, graceful/fatal
   close, and explicit adapter teardown.
6. Jemmet can keep its common `needsWrite` invariant without reading `RuntimeState.writeInterest`.
7. Public docs state units, ownership-transfer points, terminal behavior, suite assumptions, and RFC 048/050
   compatibility.
8. The canonical gate is green and the handoff records exact release/commit/archive/sidecar/GATE-RUN evidence.

## Non-goals

No TLS protocol decision, iotakt dependency, listener-wide admission policy, certificate-chain redesign,
timeout implementation, async crypto, or production-readiness promotion is part of this RFC.
