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

`negotiateAlpn` matches the client's offered list against the endpoint's allow
list and returns an `AlpnDecision` reporting a **fact**: `notOffered` (the client
sent no ALPN extension — and *only* that), `selected p` (a protocol both offered and
allowed), or `noOverlap` (the client offered ALPN but nothing overlaps — **under every
mode**). Selection order follows `mode.preference`: `serverPreference` and the strict
`requireOverlap` use the **server's** order; `clientPreferenceWithinAllowed` the
client's. The strict-vs-lenient *consequence* of `noOverlap` is the handshake caller's
policy (`mode.noOverlapPolicy`), not part of negotiation: `requireOverlap` maps it to a
fatal **`no_application_protocol`** (alert 120) *before* any
ServerHello, random, or key-schedule action — no server flight is produced (RFC
7301 §3.2), while the lenient modes proceed with no protocol selected. The alert is *classified* and the connection terminates; as with every
fatal handshake failure today, the description byte itself is not transmitted (see
[Alerts and close](./alerts-close.md)). A client sending no ALPN extension never
triggers this (it is
`notOffered`). A literally empty ALPN list or empty protocol name is rejected
earlier, at parse, as malformed.

Three proved properties back this (`Kroopt.Proofs.Config`):
`negotiateAlpn_offered_and_allowed` — **any** `selected` protocol is in *both*
lists, so kroopt never selects a protocol the client did not offer or the endpoint
did not permit; `negotiateAlpn_absent_notOffered` — an absent offer never fails;
`negotiateAlpn_requireOverlap_noOverlap` — a strict-mode non-overlapping offer is
detected as `noOverlap`. kroopt negotiates the byte-level extension; jemmet still
owns ALPN *policy* and picks the protocol handler from the reported result.

## Named-group policy (RFC 039)

Each endpoint carries a `namedGroups` policy (default `[x25519, secp256r1]`; a hardened
listener sets `[x25519]`). It is an **allow-list, and its order is ignored** — it controls
*which* ECDHE groups the listener may negotiate, not their ranking. Server preference is fixed
by `Core.groupPreference` (currently x25519 before secp256r1), so `[secp256r1, x25519]` is the
same policy as `[x25519, secp256r1]`: both still negotiate x25519 when the client offers it.
Config validation rejects a policy that is empty, has a duplicate group, or names a group the
crypto provider cannot perform. Per-endpoint ranking, if ever needed, would be a separate field
(e.g. `groupPreference`), not a reinterpretation of `namedGroups`.

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
