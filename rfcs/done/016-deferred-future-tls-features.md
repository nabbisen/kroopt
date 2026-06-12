# RFC 016 — Deferred Future TLS Features and Scope Control

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** Future  
**Depends on.** RFC 001  
**Touches.** `docs/src/` scope-control notes; standing backlog entry  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC is a standing scope-control document. It records important TLS features and adjacent capabilities that are deliberately deferred from kroopt's initial release line. Deferral does not mean rejection forever; it means each feature requires a separate RFC with security, data-model, proof, testing, and integration impact analysis.

## 2. Deferred features

- Peer X.509 path validation.
- Client role / outbound TLS.
- mTLS client certificate authentication.
- Session tickets and resumption.
- 0-RTT early data.
- HelloRetryRequest.
- KeyUpdate.
- Post-handshake authentication.
- TLS 1.2 compatibility.
- QUIC and DTLS.
- Same-port plaintext/TLS sniffing.
- Callback-based dynamic certificate selection.
- Advanced performance work such as batching, zero-copy, or async crypto workers.

## 3. Why deferral is necessary

Each deferred feature changes at least one core security invariant:

- HRR changes transcript construction.
- 0-RTT introduces replay risk and application-policy coupling.
- Tickets/resumption introduce stateful or stateless ticket protection and lifecycle concerns.
- Client mode and mTLS introduce peer path validation and trust-anchor policy.
- TLS 1.2 introduces a different handshake, record, and downgrade story.
- QUIC and DTLS are not simply TLS over a different socket.
- Same-port sniffing changes buffering and downgrade/confusion risks.

## 4. RFC requirements for future features

A future feature RFC must include:

1. threat model changes;
2. data-model changes;
3. state-machine changes;
4. transcript changes;
5. record-layer changes if any;
6. public API changes;
7. proof obligations;
8. test and fuzz requirements;
9. interop requirements;
10. migration and compatibility plan;
11. explicit non-goals.

## 5. Feature-specific notes

### 5.1 Peer X.509 path validation

Requires trust anchor management, name validation, expiry validation, path building, key usage checks, revocation policy, and error mapping. It should not be smuggled into server certificate presentation.

### 5.2 Client role

Requires outbound SNI, peer validation, client-side ALPN policy, possibly system trust-store integration or caller-supplied anchors, and different public API semantics.

### 5.3 mTLS

Requires server-side client certificate request, client Certificate/CertificateVerify handling, peer identity exposure to jemmet, authorization boundaries, and privacy-sensitive logging.

### 5.4 Session tickets and resumption

Requires ticket key lifecycle, replay/identity considerations, persistence policy, and careful proof updates for abbreviated handshakes.

### 5.5 0-RTT

Requires explicit application replay policy. It must not be implemented until jemmet can declare whether a request is replay-safe before processing.

### 5.6 HelloRetryRequest

Requires transcript special-case modeling and additional state transitions. It should be added only after the no-HRR path is stable and proven.

### 5.7 KeyUpdate

Requires application epoch rekeying, old/new key overlap rules, sequence reset handling, and proof updates.

### 5.8 TLS 1.2

Requires a separate handshake model and security review. It must not be added as a fallback from failed TLS 1.3 negotiation.

## 6. Acceptance criteria

- Deferred items are not implemented in the initial release line.
- Any PR introducing one of these features links to a new detailed RFC.
- Tests assert that unsupported features are rejected safely where applicable.
- Documentation explains that deferral is security-driven, not accidental omission.
