# jemmet integration and end-to-end HTTPS

M10 closes the v0.x acceptance target (RFC 015): jemmet consumes kroopt through a
single uniform connection abstraction, and a full HTTPS request is served
end-to-end through the modeled stack.

## One handler path, two transports

jemmet does not grow a separate HTTPS handler. It depends on the uniform
`PlainConn` abstraction — `recv` / `send` / `flush` / `close` /
`negotiatedProtocol` / `isConnected` — and a single handler runs over it. The
`:443` listener wires a kroopt `TlsConn` (which implements `PlainConn` with
exactly its public API, no new behaviour); the `:80` listener wires a
`PlainIotaktConn`. The acceptance tests run the *same* `jemmetServeOnce` handler
over both: it sees authenticated plaintext either way and never branches on
whether TLS is underneath. Same-port TLS/plaintext sniffing is not part of this
release line — the choice is explicit listener wiring.

## ALPN handoff

After the handshake, kroopt reports the negotiated ALPN through
`negotiatedProtocol`; jemmet uses it to choose its HTTP/1.1 (or future HTTP/2)
handler. kroopt negotiates the byte-level extension and nothing more — it never
selects a handler or inspects HTTP bytes. A plaintext connection reports no ALPN.

The behaviour jemmet should rely on, choosing the `requireOverlap` mode: a client
that sends **no** ALPN extension negotiates no protocol (`negotiatedProtocol` is
absent) and the handshake proceeds — jemmet falls back to HTTP/1.1. A client that
**offers** ALPN with no protocol the endpoint allows fails the handshake before
any server flight and never reaches a handler. kroopt emits a best-effort
plaintext `no_application_protocol` (alert 120) in the initial epoch (RFC 041);
peer receipt is not guaranteed under transport failure or back-pressure (see
[Alerts and close](./alerts-close.md)). When
there is overlap, the server's preference order wins. (The two lenient modes
instead proceed with no protocol on a non-overlapping offer; pick them only if
serving an unnegotiated default is preferable to failing.)

## Negative inputs never reach the handler

The security-critical acceptance cases all hold: plaintext HTTP sent to the TLS
listener is parsed as a (failed) ClientHello and never surfaces as application
bytes; garbage on the TLS listener fails the handshake and `recv` yields no
plaintext; and a TLS connection delivers nothing before `connected`. A TLS
failure never degrades to plaintext — the jemmet handler is simply never invoked
with attacker bytes.

## Redacted diagnostics

Handshake failures are surfaced as a typed, redacted `TlsErrorView`: an error
category, the alert sent/received if any, the config generation, and an SNI
*length* rather than the raw value. By construction the view has no field for
secrets, decrypted plaintext, or raw attacker-controlled messages. Bounded
non-secret `Metrics` count handshake success/failure, alerts, ALPN selections,
and resource-budget failures.

## Outbound egress and resource limits

kroopt self-bounds the per-connection outbound-ciphertext queue. Before accepting
more plaintext for encryption, `TlsConn.send` admits only a prefix whose sealed
record keeps the kroopt-owned queue within the connection's validated
`maxPendingCiphertextBytes`, so `rt.outbound.size ≤ cap` holds after any
successful send (RFC 042 A1). `TlsConn.ownedOutboundBytes` exposes that queue
size. The limits are part of the validated listener configuration
(`ResourceLimits`, RFC 042 B1), so jemmet may apply a single global default to
every listener or derive a per-listener value from its own budget — that policy
choice is jemmet's. kroopt still owns only the single-connection bound; aggregate
and listener-wide admission, and any global egress budget, remain jemmet's
responsibility. Fatal alert records are queued best-effort even when the app cap
is full (one terminal-control record), so they are not back-pressured.

> Earlier integration notes stated kroopt exposed `ownedOutboundBytes` but did not
> yet self-bound it. That was true before the RFC 042 remediation and is no longer
> the case: kroopt now self-bounds per-connection outbound ciphertext.

## Scope of the acceptance

The end-to-end test serves a real HTTP/1.1 request and response through
`TlsConn`, driving a full handshake and an application-data record over the fake
transport and fake crypto provider. **Live real-client interop is current**, not
deferred: `scripts/tls-interop.sh` runs OpenSSL `s_client`, Python, and curl
against kroopt over a real-socket reactor with the real crypto provider
(constrained profile — see the interop page). What remains is the real
**iotakt**-socket binding (the 0.107 `Transport` typeclass is exactly that seam —
an adapter, not a protocol change) and browser-grade interop, which is not yet
claimed. This milestone is interop/E2E work — classed TESTED, not PROVEN — and it
adds no new core theorems; the proved guarantees from M0–M9 continue to govern the
running connection unchanged.
