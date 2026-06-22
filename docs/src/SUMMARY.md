# Summary

[Introduction](introduction.md)

# Architecture

- [Boundary and non-goals](architecture/boundary.md)
- [Parser foundation](architecture/parser.md)
- [Record model](architecture/record-model.md)
- [Nonce, sequence, key separation](architecture/nonce-sequence.md)
- [Handshake state model](architecture/handshake.md)
- [Transcript model](architecture/transcript.md)
- [Handshake wire format (real serialization)](architecture/wire-format.md)
- [Real server-flight assembly](architecture/server-flight.md)
- [Live step-driven real handshake](architecture/live-handshake.md)
- [Real TLS 1.3 record protection](architecture/record-protection.md)
- [Certificate presentation and interop validation](architecture/cert-presentation.md)
- [Records over a real OS socket](architecture/socket-transport.md)
- [End-to-end handshake (fakes)](architecture/end-to-end.md)
- [TlsConn API and the interpreter](architecture/tlsconn-interpreter.md)
- [SNI/ALPN config and certificate presentation](architecture/config-cert.md)
- [Alerts, close_notify, and terminal policy](architecture/alerts-close.md)
- [No-secrets trace facility](architecture/trace-facility.md)
- [jemmet integration and end-to-end HTTPS](architecture/jemmet-integration.md)

# Cryptography and the trust boundary

- [Crypto provider and FFI contract](crypto/crypto-ffi-contract.md)
- [Native crypto binding: HACL* through Lean FFI](crypto/native-crypto.md)
- [Secret arena and the TLS 1.3 key schedule](crypto/key-schedule.md)
- [Enriched crypto interface and the real provider](crypto/enriched-crypto-interface.md)
- [The verified key-schedule orchestrator](crypto/key-schedule-orchestrator.md)
- [Connection provisioning and Ed25519 vector discipline](crypto/provisioning.md)
- [Vendored crypto: provenance and licensing](crypto/third-party.md)
- [Postmortem — the Ed25519 false positive](crypto/postmortem-ed25519.md)

# Interoperability

- [Constrained vs browser-grade interop](interop/constrained-vs-browser-grade.md)

# Verification

- [Theorem inventory](verification/theorem-inventory.md)
- [Proof assumptions register](verification/proof-assumptions.md)
- [Proof gates, CI, and Lean hygiene](verification/proof-gates.md)
- [Threat model and abuse cases](verification/threat-model.md)
- [Resource budgets and DoS defense](verification/resource-budgets.md)
- [Deferred features and scope control](verification/deferred-scope.md)
- [Security review checklist](security-review-checklist.md)
