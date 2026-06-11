# RFC 015 — jemmet Integration and End-to-End Acceptance

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M10  
**Depends on.** RFC 010, RFC 011, RFC 012, RFC 013  
**Touches.** jemmet integration surface; `examples/`; E2E `Tests/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines how jemmet consumes kroopt and what end-to-end behavior proves kroopt is ready as a real HTTPS layer. jemmet should not gain a separate HTTPS handler path; it should consume a uniform plaintext connection abstraction whose implementation is either raw iotakt or kroopt `TlsConn` depending on listener wiring.

## 2. Goals

- Define jemmet-facing connection abstraction requirements.
- Define HTTPS listener wiring.
- Define ALPN handoff.
- Define logging and error propagation.
- Define E2E acceptance tests with jemmet + kroopt + iotakt.

## 3. Integration shape

```text
iotakt accepts TCP connection
  -> listener config chooses plaintext or TLS
  -> plaintext: jemmet receives raw plaintext connection adapter
  -> TLS: kroopt creates TlsConn, completes/progresses handshake
  -> jemmet receives same plaintext recv/send/flush/close shape
```

No same-port TLS sniffing in the initial release line.

## 4. jemmet-facing abstraction

jemmet needs an abstraction equivalent to:

```lean
class PlainConn where
  recv  : IO ReadResult
  send  : ByteArray -> IO WriteResult
  flush : IO FlushResult
  close : CloseIntent -> IO CloseResult
  peerInfo : PeerInfo
  negotiatedProtocol : Option ALPNProtocol
```

`TlsConn` implements/adapts to this shape. Plain iotakt connections also implement/adapt to this shape.

## 5. ALPN handoff

kroopt reports selected ALPN after handshake completion. jemmet uses the result to select HTTP/1.1 or future HTTP/2 handler. kroopt must not select handlers or inspect HTTP bytes.

If no ALPN is selected, jemmet policy decides whether to default to HTTP/1.1 or reject the connection. kroopt only enforces the configured TLS negotiation policy.

## 6. Error handling

Handshake errors are surfaced as typed, redacted failures. jemmet may log:

- failure category;
- TLS phase;
- redacted SNI preview;
- selected config generation if any;
- alert sent/received;
- no secrets and no full raw ClientHello.

## 7. E2E tests

Required tests:

- `curl https://...` receives a jemmet HTTP/1.1 response.
- OpenSSL `s_client` completes TLS 1.3 handshake.
- SNI route A and route B select different certificate configs.
- ALPN `http/1.1` is reported to jemmet.
- malformed TLS input does not reach jemmet as plaintext.
- plaintext HTTP sent to TLS listener fails cleanly and does not invoke HTTP handler.
- kroopt requires no iotakt source changes.

## 8. Operational diagnostics

kroopt should expose counters or event hooks for:

- handshake success/failure count;
- alert categories;
- config generation;
- selected ALPN counts;
- resource-budget failures;
- sanitizer/KAT status at build/test time, not runtime.

Diagnostics must be non-secret and bounded.

## 9. Security considerations

- jemmet must never see unverified TLS bytes as HTTP.
- ALPN does not authorize arbitrary protocol activation; jemmet policy still controls handlers.
- TLS failures must not degrade to plaintext.
- Listener wiring must make plaintext vs TLS explicit.

## 10. Acceptance criteria

- jemmet serves a real HTTPS request through kroopt and iotakt.
- Plaintext and TLS connection adapters share one jemmet handler path.
- OpenSSL and curl interop pass.
- Negative TLS input never reaches HTTP parsing.
- Operational errors are redacted and typed.
