# RFC 001 — Boundary and Non-Goals

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M0  
**Depends on.** None.  
**Touches.** `docs/src/boundary.md`; module dependency rules; public-surface module list  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC fixes the architectural boundary of kroopt before any implementation starts. kroopt is a TLS secure-channel library. It consumes an already accepted non-blocking byte connection from iotakt, drives TLS protocol logic through its verified core and interpreter, borrows cryptographic primitives from HACL\*/EverCrypt, and exposes a plaintext byte connection to jemmet or another application protocol layer.

This RFC is intentionally strict. TLS projects fail when boundaries blur: the transport layer starts understanding TLS, the TLS layer starts making HTTP decisions, or runtime integration starts bypassing the proof model. kroopt must not do any of those.

## 2. Goals

- Define what kroopt owns and what it does not own.
- Keep iotakt, kroopt, and jemmet independently auditable.
- Establish the no-iotakt-change rule for kroopt convenience.
- Establish the crypto trust boundary: kroopt borrows primitives and proves protocol orchestration.
- Establish scope exclusions for the initial implementation path.

## 3. Non-goals

- No TCP socket creation, fd lifecycle, epoll, or syscall ownership.
- No HTTP parsing, routing, response handling, or application buffering.
- No implementation of cipher primitives, hashes, KDFs, signature algorithms, or PRNGs.
- No TLS 1.2, QUIC, DTLS, 0-RTT, tickets/resumption, HelloRetryRequest, KeyUpdate, post-handshake authentication, client role, or mTLS in the initial release line.
- No peer certificate path validation in server mode.
- No same-port plaintext/TLS sniffing in the initial release line.

## 4. Layer ownership

| Layer | Owns | Must not own |
|---|---|---|
| iotakt | fd identity, non-blocking recv/send, readiness, closeConnection | TLS state, encryption, plaintext semantics |
| kroopt | TLS state, records, alerts, key orchestration, SNI/ALPN negotiation, server cert presentation | syscalls, HTTP semantics, primitive crypto implementations, peer cert path validation |
| jemmet | HTTP semantics, routing, handler lifecycle, ALPN policy decision, listener wiring | TLS record details, key schedule, crypto FFI, fd lifecycle |
| HACL\*/EverCrypt | primitive crypto correctness and constant-time-sensitive primitive behavior | TLS state machine, iotakt integration, jemmet policy |

## 5. Boundary contracts

### 5.1 Downward contract with iotakt

kroopt receives an established iotakt connection represented by a generation-protected `FdKey`. All transport I/O is expressed through iotakt primitives. iotakt readiness is a hint, not a guarantee. A readable event may still yield `wouldBlock`, and a writable event may still make only partial progress.

kroopt must not request a TLS-aware iotakt API. If such a need appears, the design must be re-evaluated; it is presumed to be a boundary violation unless proven otherwise.

### 5.2 Upward contract with jemmet

kroopt exposes `TlsConn` as a plaintext byte channel with semantics deliberately close to the plaintext iotakt connection shape. jemmet uses one connection abstraction and does not branch its handler logic between HTTP and HTTPS paths. ALPN policy belongs to jemmet; kroopt merely negotiates within the configured offer and reports the result.

### 5.3 Crypto contract

kroopt does not implement cryptographic primitives. It calls a crypto provider through a narrow interface. For production, that provider is HACL\*/EverCrypt through a C shim and Lean FFI. The correctness of the primitives is ASSUMED from the provider; the correctness of which primitive is called, in which state, with which epoch, key, nonce, transcript, and input is kroopt's responsibility.

## 6. Security rationale

The boundary prevents three classes of security failure:

1. **Attack-surface relocation.** Putting an unverified TLS terminator in front of jemmet would move the internet-facing attack surface out of the verified stack.
2. **State confusion.** Mixing transport, TLS, and HTTP logic encourages shortcuts such as emitting plaintext before handshake completion or interpreting unverified bytes.
3. **Proof irrelevance.** If the runtime driver implements protocol decisions outside the verified core, the proof can become ornamental.

## 7. Public surface implications

This RFC implies the following public modules must remain small and stable:

```lean
Kroopt.Conn.TlsConn
Kroopt.Conn.Config
Kroopt.Conn.Error
Kroopt.Core.State       -- visible for diagnostics and proof-level tests, not for mutation
Kroopt.Core.Alert       -- visible as typed error information
```

The public API must not expose internal raw traffic secrets, raw transcript secrets, raw crypto pointers, parser internals, or iotakt implementation details beyond `FdKey` and readiness/result concepts.

## 8. Acceptance criteria

- The repository documents the iotakt/kroopt/jemmet boundary.
- Module dependencies enforce the pure-core / crypto / interpreter split.
- No kroopt module performs syscalls directly.
- No public kroopt API exposes raw secret bytes.
- Initial scope exclusions are documented and linked to RFC 016.

## 9. Rejection criteria

Reject implementation changes that:

- add TLS-specific APIs to iotakt for kroopt convenience;
- perform HTTP decisions inside kroopt;
- call HACL\*/EverCrypt directly from the verified core;
- parse or emit TLS records from jemmet;
- introduce unbounded buffers or hidden application buffering below jemmet.
