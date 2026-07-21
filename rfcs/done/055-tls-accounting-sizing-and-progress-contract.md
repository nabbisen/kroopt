# RFC 055 — TLS Accounting, Sizing, and Progress Contract

**Project.** kroopt
**Status.** Implemented (`0.126.0`; implementation `cfda893`, release `877e54d`, run `29370919042`)
**Type.** Blocking downstream integration/API fix
**Target milestone.** AR-I integration enabler, before AR1 protocol changes
**Requires completion of.** [RFC 010](../done/010-tlsconn-api-nonblocking-interpreter.md), [RFC 019](../done/019-resource-budgets-backpressure-and-dos-defense.md), [RFC 042](../done/042-resource-limit-enforcement.md)
**Coordinates with.** [RFC 047](../proposed/047-monotonic-deadlines-and-timeout-enforcement.md), [RFC 048](../proposed/048-validated-construction-and-protected-epoch-fail-closed.md), [RFC 050](../proposed/050-bounded-certificate-chain-presentation.md), [RFC 052](../proposed/052-jemmet-iotakt-production-path-acceptance.md)
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

## Implementation evidence

Implementation commit `cfda89310c040ef893e67c0c46e2889c140326eb` added the accounting, sizing,
reserve, and progress APIs together with the connection and iotakt-boundary tests. GitHub Actions run
[`29298648079`](https://github.com/nabbisen/kroopt/actions/runs/29298648079) checked out that exact commit and
observed:

- the canonical `kroopt-gate/v3` `full-release` profile passing 42/42;
- the release-machinery pass-detection, dependency, registry-drift, ledger, and provenance negative controls
  passing;
- the ASan/UBSan harness compiling and passing under both GCC 12.5.0 and GCC 16.1.0 with Lean 4.15.0.

The implementation CI gate artifact was retained as artifact `8297742336`; GitHub reported its ZIP SHA-256
as `ae8938e7654df165f6b1b2d366329994c86657a59d860436e9dc5c8e9e1c377b`.

Release `0.126.0` is exact commit `877e54d1ce3a45ca88030052b7dedea99358ea56`. Tagged workflow run
[`29370919042`](https://github.com/nabbisen/kroopt/actions/runs/29370919042) passed the canonical profile
42/42, all release-machinery groups, and strict `--require-release` verification. It published:

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `kroopt-0.126.0.tar.gz` | 824935 | `c311bf854f1bfc78426fbc47292fb5756cebe33c2f127b1d197487afef83c451` |
| `kroopt-0.126.0.release-verification.json` | 27739 | `ce621f26a828d0da97e6a834d38ee78f2f7d4b72b4b4a54d21b6e3889bf0e579` |
| `kroopt-0.126.0.GATE-RUN.md` | 2080 | `4f81a63b2bb89452b1362cfd584b8ad671f75d9aae7b45913e52549778a729e1` |
