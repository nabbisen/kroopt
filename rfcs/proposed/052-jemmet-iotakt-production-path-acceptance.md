# RFC 052 — jemmet+iotakt Production-Path Acceptance

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking downstream integration/acceptance theme  
**Target milestone.** AR3  
**Requires completion of.** AR1, AR2, [RFC 010](../done/010-tlsconn-api-nonblocking-interpreter.md), [RFC 047](047-monotonic-deadlines-and-timeout-enforcement.md), [RFC 050](050-bounded-certificate-chain-presentation.md), [RFC 051](051-release-gate-portability-and-canonical-evidence.md)  
**Coordinates with.** [RFC 015](015-jemmet-integration-and-e2e-acceptance.md), [RFC 026](026-compatibility-interop-and-negative-matrix.md)  
**Touches.** kroopt binding reference/gates; jemmet-owned iotakt adapter and HTTPS fixture; handoffs  

## Review finding

The review confirmed that the real ownership graph is not yet canonical evidence. kroopt has a tested
translation reference and socket stand-ins, but the real adapter belongs to jemmet and real
jemmet+iotakt+kroopt HTTPS E2E remains pending.

## Decision

kroopt keeps no iotakt dependency edge. It publishes `TlsConn`, `Transport`, TLS-negative assertions, and a
gated translation contract. jemmet owns `Jemmet/Conn/IotaktTransport.lean`, instantiating that contract over
iotakt. Acceptance is a cross-project version-pinned run, not an in-repository fake renamed as production.

This RFC coordinates and sharpens existing [RFC 015](015-jemmet-integration-and-e2e-acceptance.md) and
[RFC 026](026-compatibility-interop-and-negative-matrix.md); it does not supersede their design scope.
The iotakt binding gate entry is owned and registered by
[RFC 051](051-release-gate-portability-and-canonical-evidence.md); this RFC consumes that entry and owns the
real downstream conformance/E2E evidence.

## Work breakdown

1. Consume the canonical kroopt iotakt translation-reference entry registered by
   [RFC 051](051-release-gate-portability-and-canonical-evidence.md) and verify its
   frozen contract version in the cross-project run.
2. Freeze versioned signatures for fd generation, readiness hints, partial writes, EOF, interest, and close.
3. Implement/verify the adapter in jemmet with zero iotakt source changes.
4. Run HTTPS through real iotakt readiness and the real kroopt provider.
5. Exercise ALPN/SNI, leaf+intermediate chain, backpressure, partial I/O, timeouts, graceful close, fatal
   alerts, malformed TLS input, and plaintext-on-TLS-listener negatives.
6. Verify release sidecars/pins and retain cross-project logs/artifact hashes.

## Acceptance criteria

1. A real HTTPS request/response passes through jemmet + kroopt + iotakt with independent clients.
2. Negative TLS inputs never reach the HTTP handler and never downgrade to plaintext.
3. `wrote n`, `wouldBlock`, flush, owned-output, deadline, and close semantics match at the adapter boundary.
4. No kroopt source or release-sidecar dependency on iotakt is introduced.
5. The handoff identifies exact kroopt/jemmet/iotakt revisions and observed commands.
6. [RFC 015](015-jemmet-integration-and-e2e-acceptance.md) and
   [RFC 026](026-compatibility-interop-and-negative-matrix.md) status and production-readiness claims are
   updated from this evidence.

## Non-goals

Browser-grade breadth, HTTP/2 semantics, listener-wide admission control, and async crypto remain their own
RFCs. The fixture may use HTTP/1.1 but kroopt still does not own HTTP logic.
