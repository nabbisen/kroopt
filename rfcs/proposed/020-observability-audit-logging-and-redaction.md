# RFC 020 — Observability, Audit Logging, and Redaction

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.3; v0.4  
**Depends on.** RFC 010, RFC 011, RFC 012, RFC 013, RFC 017, RFC 018  
**Touches.** `Kroopt/` event taxonomy; `docs/src/errors-and-alerts.md`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's externally visible observability model: metrics, trace
events, audit events, error categories, and redaction rules. Observability is
necessary for operating an edge TLS layer, but TLS diagnostics can easily leak
secret material, plaintext, certificate details, or attacker-controlled blobs.

The design therefore uses structured, redacted, category-based events instead of
free-form logging from deep protocol code.

---

## 2. Goals

1. Provide enough data for operators to diagnose handshake failures,
   configuration errors, and interoperability problems.
2. Prevent secret, plaintext, and raw hostile input leakage.
3. Keep logs stable for jemmet integration.
4. Separate security-audit events from high-volume trace events.
5. Make log safety testable.

---

## 3. Event taxonomy

### 3.1 Trace events

For development and debug builds; may be disabled in production.

Examples:

- connection accepted by kroopt;
- input bytes received count;
- parser state advanced;
- output action emitted;
- crypto operation requested/completed by type only;
- progress stopped on would-block.

### 3.2 Audit events

For production-relevant state changes:

- handshake started;
- handshake succeeded;
- handshake failed by category;
- SNI matched config entry;
- ALPN selected;
- fatal alert sent/received;
- close_notify sent/received;
- resource budget exceeded;
- config snapshot loaded/rejected.

### 3.3 Metrics

Counters and histograms:

- handshakes started/succeeded/failed;
- failure categories;
- negotiated cipher suite;
- negotiated ALPN;
- record decrypt failures;
- resource-budget failures;
- pending ciphertext queue high-water mark;
- handshake duration;
- bytes encrypted/decrypted;
- fatal alerts by description.

---

## 4. Redaction rules

Forbidden in logs and metrics labels:

1. private key bytes or handles that can be correlated to memory addresses;
2. traffic secret material;
3. plaintext HTTP/application bytes;
4. raw TLS records or raw ClientHello blobs;
5. raw certificate DER;
6. unescaped attacker-controlled strings;
7. full file paths to private keys unless deployment explicitly enables them.

Allowed with sanitization:

1. public cipher suite identifier;
2. TLS version;
3. ALPN protocol from a configured allow-list;
4. normalized SNI after length cap, escaping, and optional hashing policy;
5. certificate configuration id, not raw certificate;
6. alert description;
7. byte counts and duration buckets.

---

## 5. Public event API

Illustrative API:

```lean
inductive SecurityEvent where
  | handshakeStart (conn : ConnTraceId)
  | handshakeSuccess (conn : ConnTraceId) (summary : HandshakeSummary)
  | handshakeFailure (conn : ConnTraceId) (reason : PublicFailureReason)
  | alertSent (conn : ConnTraceId) (alert : AlertDescription)
  | alertReceived (conn : ConnTraceId) (alert : AlertDescription)
  | budgetExceeded (conn : ConnTraceId) (budget : BudgetKind)
  | configRejected (reason : ConfigErrorSummary)

structure HandshakeSummary where
  tlsVersion : TlsVersion
  cipherSuite : CipherSuite
  alpn : Option AlpnProtocol
  sniClass : SniLogValue
```

`ConnTraceId` is not the raw fd and not a pointer. It is generated for
correlation within a process lifetime.

---

## 6. Error categorization

Public failure categories must be coarse enough to avoid oracle-style detail but
specific enough for operations:

- parse_error;
- unsupported_protocol;
- unsupported_cipher_suite;
- unsupported_group;
- bad_certificate_config;
- bad_finished;
- decrypt_error;
- resource_limit;
- timeout;
- transport_error;
- internal_error.

Detailed internal debug strings may exist only in test/dev builds and must obey
redaction.

---

## 7. Internal design

Protocol code does not call a logger directly. It emits typed events or returns
structured errors. The outer integration layer decides how to route them.

```text
Core step → OutputAction / TlsError / SecurityEvent candidate
Interpreter → attaches connection trace id and transport context
jemmet integration → routes to logging/metrics backend
```

This prevents accidental string formatting of secret-bearing internal state.

---

## 8. Tests

1. Redaction snapshot tests for representative errors.
2. Property test that `SecurityEvent` rendering never invokes `Repr` on secret
   types.
3. Malicious SNI with control characters is escaped or hashed.
4. Raw ClientHello is unavailable to production log rendering.
5. Config rejection events identify configuration entry id, not private key
   contents.

---

## 9. Acceptance criteria

1. A typed event taxonomy exists before v0.3.
2. Redaction tests are part of CI.
3. Public error rendering is stable enough for jemmet to consume.
4. Secret-bearing types cannot be accidentally printed through event rendering.
5. Documentation includes an operator-facing event and metric reference.
