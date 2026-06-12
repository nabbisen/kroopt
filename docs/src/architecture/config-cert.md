# SNI/ALPN configuration and certificate presentation

M8 makes server configuration real (RFC 011, 012). Until now the handshake
selected a cipher suite from the ClientHello but had no notion of an SNI→cert
table, ALPN policy, or certificate presentation. M8 adds an immutable, validated
configuration model and wires deterministic selection into the handshake.

## Immutable validated config

`ServerConfig` is the raw, pre-validation table: a default endpoint, a list of
SNI routes, and an ALPN selection mode. `validateServerConfig` turns it into a
`ValidatedServerConfig` stamped with a `ConfigGeneration`, or rejects it
deterministically — ambiguous routes give `ambiguousSni`, an endpoint with an
incompatible cert/key or no cipher suite is refused. The validated object is
immutable; reload produces a *new* generation, and in-flight connections keep the
generation they started with, so certificate selection, transcript construction,
and CertificateVerify signing never observe a half-updated config (RFC 011 §6).
This is why the connection state carries `serverConfig`, and why
`validateServerConfig_preserves_generation` is proved.

## Deterministic SNI and ALPN selection

`selectEndpoint` resolves an (already-validated) SNI name to an endpoint: an exact
match is preferred over a wildcard, and absent or unmatched SNI falls back to the
default endpoint. Wildcards match a single leftmost label only. Selection is a
pure function with no callbacks, so it cannot block, recurse into user code, or
produce a non-reproducible result during ClientHello processing (RFC 011 §8).

`negotiateAlpn` intersects the client's offered list with the endpoint's allow
list under the configured policy (server-preference, client-preference, or
require-overlap). Its proved property is the one that matters for §8:
`negotiateAlpn_offered_and_allowed` — **any** protocol it returns is in *both*
lists, so kroopt can never select a protocol the client did not offer or the
endpoint did not permit. kroopt negotiates the byte-level extension; jemmet still
owns ALPN *policy* and picks the protocol handler from the reported result.

## Certificate presentation, not validation

kroopt **presents** a configured chain and proves key possession via
CertificateVerify; it does not validate a peer chain in server mode. The chain
stays opaque DER; only minimal leaf metadata is modelled, for two pure checks:
`validateEndpointCertKey` (the config lint — leaf key kind matches the private
key kind, the chain is non-empty and within size bounds, at least one configured
scheme is usable) and `selectSignatureScheme` (a CertificateVerify scheme the
client offered, the endpoint configured, and the leaf key can produce). The
latter's soundness is proved: a selected scheme is never a downgrade to an
unoffered or incompatible one. Expiry/name checks remain optional lint and are
explicitly not peer path validation (deferred to the client/mTLS RFC).
