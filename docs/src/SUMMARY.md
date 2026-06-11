# Summary

[Introduction](introduction.md)

# Architecture

- [Boundary and non-goals](boundary.md)
- [Parser foundation](parser.md)
- [Record model](record-model.md)
- [Nonce, sequence, key separation](nonce-sequence.md)
- [Handshake state model](handshake.md)
- [Transcript model](transcript.md)
- [End-to-end handshake (fakes)](end-to-end.md)
- [Crypto provider and FFI contract](crypto-ffi-contract.md)
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