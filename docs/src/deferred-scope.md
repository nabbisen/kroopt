# Deferred features and scope control

kroopt's initial release line is deliberately narrow (RFC 016): TLS 1.3 only,
server role only, no HelloRetryRequest. Features that are deferred or excluded —
TLS 1.2, DTLS, QUIC, 0-RTT/early data, session tickets/resumption, KeyUpdate,
post-handshake auth, renegotiation, compression, mTLS, and the client role — are
not partially implemented and must not be silently activatable.

Scope is enforced, not just documented. A ClientHello that does not genuinely
offer TLS 1.3 is refused rather than downgraded: the parser requires a
`supported_versions` extension that lists 0x0304, so a ClientHello with no
`supported_versions`, or one offering only TLS 1.2 (0x0303), fails cleanly. The
absence of an acceptable X25519 `key_share` fails too (no HRR). These are
exercised by the hardening suite.

Feature gates must never silently change security semantics: enabling any
deferred feature is an explicit, RFC-gated change, not a build flag that flips a
default. Each deferred feature returns through its own future RFC (RFC 016's
descendants) with its own model, proofs, and tests.
