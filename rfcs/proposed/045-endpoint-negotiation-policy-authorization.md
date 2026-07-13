# RFC 045 — Endpoint Negotiation Policy Authorization

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking correctness/security fix  
**Target milestone.** AR1  
**Requires completion of.** [RFC 011](../done/011-sni-alpn-configuration-model.md) (endpoint config), [RFC 034](../done/034-provider-capability-honesty-and-entropy.md) (capability honesty), [RFC 039](../done/039-named-group-policy-and-enforcement.md) (group authorization)  
**Touches.** `Kroopt/Core/{Config,Handshake}.lean`, `Kroopt/Parse/Handshake.lean`, proofs and negotiation tests  

## Review finding

Architecture review B1 found that the parser globally selects a cipher suite before SNI endpoint resolution,
while the core records that choice without checking `EndpointConfig.cipherSuites`. The endpoint allow-list is
therefore not authoritative.

## Decision

Parsing reports client offers as facts. The core resolves SNI, then selects all negotiated dimensions from
the intersection of client offers, selected-endpoint policy, and validated provider capability. No parser
function is allowed to finalize a policy decision.

The server preference is the fixed core-owned order
`chacha20Poly1305Sha256`, `aes128GcmSha256`, `aes256GcmSha384`. Endpoint lists are unordered allow-lists;
their order has no negotiation meaning. Selection scans this one preference list and chooses the first suite
that is client-offered, endpoint-allowed, and supported by the validated provider.

The fixed order is a public compatibility decision with one audit point, `Core.cipherSuitePreference`.
Adding a suite appends it by default. Reordering existing suites or inserting ahead of one requires a
separate accepted RFC, interoperability evidence, and a release-note compatibility callout. Once
ServerHello commits to a suite, provider failure is fatal: the server never retries a less-preferred suite,
so failure cannot create an attacker-directed downgrade path. Unknown and GREASE offers are ignored as
offers, not converted into preference entries.

## Work breakdown

1. Replace `ValidClientHello.selectedSuite` with bounded recognized/offered suite facts.
2. Add `Core.cipherSuitePreference` with the exact order above and a total core `selectSuite` over client
   offers, endpoint policy, validated provider capabilities, and that preference.
3. Make required provider hashes derive from the selected/allowed suites and fail config validation early.
4. Record a redaction-safe negotiation trace containing ids/categories only.
5. Prove selection authorization and crypto-operation consistency.
6. Add SNI-route, client-order, no-overlap, unknown/GREASE, and provider-mismatch tests.

## Required proofs

- a selected suite was offered by the client;
- a selected suite is allowed by the resolved endpoint;
- a selected suite is supported by the validated provider;
- no disallowed suite reaches state, key schedule, record metadata, or a crypto action;
- selection is the first authorized overlap in `Core.cipherSuitePreference`, independent of client and
  endpoint list ordering;
- no-overlap fails before server-flight or key-schedule output.

## Acceptance criteria

1. Adversarial client ordering cannot bypass an endpoint allow-list.
2. Two SNI routes with different suite policies negotiate only their own allowed suites.
3. Mismatch produces the specified fatal alert, no plaintext, and no server flight.
4. Proof inventory, trust matrix, docs, replay corpus, and live interop are updated.
5. The canonical gate is green with the new tests registered.
6. Reordering client or endpoint allow-lists does not change selection when the authorized set is unchanged.

## Non-goals

This RFC does not add new cipher suites or change provider implementations; breadth remains
[RFC 035](035-browser-grade-crypto-surface.md).
