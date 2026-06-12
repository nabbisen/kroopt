# Summary

[Introduction](introduction.md)

# Architecture

- [Boundary and non-goals](boundary.md)
- [Parser foundation](parser.md)
- [Record model](record-model.md)
- [Nonce, sequence, key separation](nonce-sequence.md)
- [Handshake state model](handshake.md)
- [Transcript model](transcript.md)
- [Handshake wire format (real serialization)](wire-format.md)
- [Real server-flight assembly](server-flight.md)
- [Live step-driven real handshake](live-handshake.md)
- [Real TLS 1.3 record protection](record-protection.md)
- [Certificate presentation and interop validation](cert-presentation.md)
- [Records over a real OS socket](socket-transport.md)
- [End-to-end handshake (fakes)](end-to-end.md)
- [Crypto provider and FFI contract](crypto-ffi-contract.md)
- [Native crypto binding (v0.3): HACL* through Lean FFI](native-crypto.md)
- [Secret arena and the TLS 1.3 key schedule (M13)](key-schedule.md)
- [Enriched crypto interface and the real provider (M14)](enriched-crypto-interface.md)
- [The verified key-schedule orchestrator (M15)](key-schedule-orchestrator.md)
- [Connection provisioning and Ed25519 vector discipline](provisioning.md)
- [Postmortem — the Ed25519 false positive](postmortem-ed25519.md)
- [Vendored crypto: provenance and licensing](third-party.md)
- [TlsConn API and the interpreter](tlsconn-interpreter.md)
- [SNI/ALPN config and certificate presentation](config-cert.md)
- [Alerts, close_notify, and terminal policy](alerts-close.md)
- [jemmet integration and end-to-end HTTPS](jemmet-integration.md)

# Verification

- [Theorem inventory](theorem-inventory.md)
- [Proof assumptions register](proof-assumptions.md)

- [Threat model and abuse cases](threat-model.md)
- [Resource budgets and DoS defense](resource-budgets.md)
- [Deferred features and scope control](deferred-scope.md)
- [Proof gates, CI, and Lean hygiene](proof-gates.md)