# RFC 021 — Configuration Lifecycle and Reload

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** v0.3 (snapshots); v0.4 (reload)  
**Depends on.** RFC 011, RFC 012, RFC 018, RFC 020  
**Touches.** `Kroopt/Conn/Config.lean`; config snapshot lifecycle  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines how kroopt configuration is loaded, validated, snapshotted,
used by connections, and reloaded. kroopt configuration contains security-
critical policy: protocol versions, cipher suites, resource limits, SNI mapping,
ALPN offers, certificate chains, and private-key handles. Partial or mutable
configuration visibility is a security risk.

---

## 2. Goals

1. Validate configuration before any listener accepts TLS using it.
2. Make running connections observe an immutable config snapshot.
3. Support future reload without mutating active connection policy.
4. Define deterministic SNI/ALPN matching under overlapping rules.
5. Ensure retired configs release secret handles only after last use.

---

## 3. Configuration states

```text
RawConfig
  → parse
ParsedConfig
  → validation + lint + secret import
ValidatedConfigSnapshot
  → used by new TlsConn instances
RetiringConfigSnapshot
  → still used by existing connections, not by new ones
RetiredConfigSnapshot
  → all handles freed/zeroized
```

---

## 4. Validation rules

A config snapshot is valid only if:

1. at least one supported cipher suite is enabled;
2. TLS 1.3 is enabled and TLS 1.2 fallback is not implicitly enabled;
3. resource limits pass minimum/maximum sanity checks;
4. SNI patterns are valid and deterministic;
5. a default certificate policy is explicitly configured or intentionally absent
   with documented failure behavior;
6. each certificate chain is loadable as opaque DER;
7. each private key imports into the provider as a `SecretKeyHandle`;
8. each leaf certificate is compatible with its private key for configured
   signature schemes;
9. ALPN offers are non-empty for listeners that require HTTP routing;
10. logging and SNI display policy is explicit.

---

## 5. Deterministic SNI matching

Recommended rule order:

1. exact hostname match;
2. wildcard match with longest suffix;
3. explicit default entry;
4. fail handshake with configured alert if no match.

Overlapping patterns that would produce ambiguous results are rejected at config
validation, unless deterministic priority is explicitly encoded.

---

## 6. ALPN policy

kroopt negotiates from a configured allow-list but does not decide HTTP behavior.

Rules:

1. ALPN strings must be configured as validated protocol identifiers.
2. Unknown client ALPN values are ignored unless policy requires fail-closed.
3. Empty ALPN negotiation result is allowed only if the listener policy permits
   default protocol behavior.
4. The negotiated value is exposed to jemmet after handshake completion.

---

## 7. Reload model

Reload is atomic:

```text
new raw config parsed
  → all validation and secret import succeed
  → publish new snapshot for future connections
  → old snapshot marked retiring
  → old snapshot freed after active refcount reaches zero
```

If validation fails, the old snapshot remains active.

Reload must not:

1. mutate active connection config;
2. replace private key handles out from under an active handshake;
3. change resource limits for active connections;
4. partially publish SNI/ALPN tables.

---

## 8. Internal design

Illustrative types:

```lean
structure ConfigSnapshotId where value : UInt64

structure ValidatedServerConfig where
  id : ConfigSnapshotId
  protocol : ProtocolPolicy
  resources : ResourceLimits
  sniTable : SniTable
  certStore : CertStore
  logging : LoggingPolicy

structure ConfigHandle where
  snapshot : ValidatedServerConfig
  -- implementation may use refcount or runtime-managed ownership
```

---

## 9. Tests

1. Valid config loads and produces a snapshot id.
2. Invalid private key/certificate pairing is rejected.
3. Ambiguous SNI wildcard table is rejected.
4. Reload failure keeps old config active.
5. Existing connection continues using old snapshot after reload.
6. Retired snapshot releases secret handles after last connection closes.

---

## 10. Acceptance criteria

1. Config validation is complete before v0.3 network tests.
2. Config snapshots are immutable.
3. Reload is atomic or explicitly deferred with the snapshot model already in
   place.
4. SNI/ALPN behavior is deterministic and documented.
5. Config lifecycle events are observable through RFC 020.
