# RFC 026 — Compatibility, Interop, and Negative Matrix

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.3; v0.4  
**Depends on.** RFC 006, RFC 009, RFC 010, RFC 011, RFC 012, RFC 013, RFC 014  
**Touches.** interop harness in `Tests/`; `docs/src/interop.md`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the compatibility and interoperability test matrix for kroopt.
Interop is TESTED, not PROVEN. The matrix must remain explicit so project status
is not overstated and so unsupported TLS features fail cleanly rather than
silently degrading security.

---

## 2. Supported positive matrix

Initial positive matrix:

| Client | TLS | KEX | AEAD | Auth | ALPN | SNI |
|---|---|---|---|---|---|---|
| OpenSSL `s_client` | 1.3 | X25519 | AES-128-GCM | Ed25519/ECDSA-P256 | yes | yes |
| curl with OpenSSL or equivalent | 1.3 | X25519 | AES-128-GCM/ChaCha20-Poly1305 | Ed25519/ECDSA-P256 | yes | yes |
| Mainstream browser | 1.3 | X25519 | negotiated supported suite | configured cert | HTTP/1.1 ALPN | yes |

The exact versions used in CI/release notes must be recorded, because client
behavior changes over time.

---

## 3. Required negative matrix

| Case | Expected result |
|---|---|
| TLS 1.2 only client | fail cleanly; no fallback |
| Missing supported_versions | fail cleanly |
| Missing X25519 key_share | fail cleanly; no HRR |
| Duplicate extension | fail cleanly |
| Unsupported group only | fail cleanly |
| Unsupported signature scheme only | fail cleanly |
| Bad Finished | fatal alert |
| Bad AEAD tag | fatal alert; no plaintext |
| Oversized record | fatal record_overflow |
| KeyUpdate | unexpected message alert |
| Post-handshake auth | unexpected message alert |
| 0-RTT data | reject; no early data accepted |
| close_notify then app data | terminal; no plaintext |

---

## 4. Interop harness

Tests should support:

1. launching kroopt over fake or real iotakt loopback;
2. generating temporary test certificates;
3. invoking OpenSSL/curl commands;
4. capturing structured kroopt events;
5. verifying negotiated ALPN/SNI/cipher;
6. checking plaintext echo correctness;
7. isolating flaky environmental failures from protocol failures.

---

## 5. Browser testing

Browser tests are operational smoke tests, not exhaustive proof. They should
verify:

1. page load through jemmet HTTPS;
2. certificate accepted when test root is installed or local trust is configured;
3. ALPN negotiation produces expected handler selection;
4. failure page or connection refusal for unsupported config is deterministic.

---

## 6. Recording known limitations

`docs/src/interop.md` must list:

- supported TLS versions;
- supported cipher suites;
- supported groups;
- supported signature algorithms;
- unsupported features and their failure behavior;
- tested clients and versions;
- known deviations or operational caveats.

---

## 7. Acceptance criteria

1. Positive OpenSSL and curl tests pass before v0.3 acceptance.
2. Negative matrix cases are deterministic and do not crash.
3. Browser smoke testing is documented before v0.4 acceptance.
4. Unsupported features are listed as deliberate non-goals, not accidental gaps.
5. Interop results are reflected in the proof/trust/test matrix as TESTED.

## Progress — live handshake interop landed

`scripts/tls-interop.sh` runs the kroopt verified core + production interpreter as a TLS 1.3 server
(`Tests/LiveServer.lean`, real OS entropy, fixture Ed25519 cert) on an AF_UNIX socket and completes a
full handshake against two independent clients: **OpenSSL 3.0 `s_client`** and **Python `ssl`**, both
negotiating `TLS_CHACHA20_POLY1305_SHA256` and reaching `connected`. Each validates kroopt's wire bytes
end to end (ServerHello, encrypted flight, presented certificate, CertificateVerify signature, server
Finished) and kroopt verifies the client's Finished. Scope: handshake only, over a real OS socket (not
yet iotakt), no app-data round-trip yet; the negative/fuzz matrix and browser/curl breadth remain.

### Progress — application-data round-trip (0.50.0-dev)

Beyond the handshake, the live server now completes a post-handshake application-data round-trip with both
OpenSSL `s_client` and Python `ssl`: each client sends an application record (decrypted server-side under
the client traffic key) and reads kroopt's sealed response (under the server traffic key). Delivery is
demand-driven per RFC 004 §9 (`transportBytes` buffers, `appRecvRequested` delivers, `appSend` responds).
Still deferred: curl/browser breadth, a negative/fuzz interop matrix, and graceful `close_notify`.
