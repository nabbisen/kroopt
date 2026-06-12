# RFC 017 — Threat Model and Abuse Cases

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** Cross-cutting (M0; current before v0.3)  
**Depends on.** RFC 001, RFC 002, RFC 003, RFC 004, RFC 013, RFC 014  
**Touches.** `docs/src/threat-model.md`; security sections in all implementation RFCs  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's threat model, attacker capabilities, excluded threats,
security assumptions, and abuse cases. It is not an implementation feature by
itself. It is the security lens that all parser, record, handshake, FFI,
configuration, logging, and runtime RFCs must pass through.

kroopt is an internet-edge TLS secure-channel layer. The remote peer may be
malicious, malformed, slow, resource-exhausting, or protocol-aware. The local
application, jemmet, is trusted not to intentionally violate the public API
contract, but kroopt must still defend against accidental misuse through typed
configuration, stateful APIs, and explicit error semantics.

---

## 2. Goals

1. Define attacker capabilities for all externally influenced data.
2. Identify assets: plaintext, keys, traffic secrets, transcript integrity,
   connection state, resource budgets, configuration correctness, and audit
   integrity.
3. Map abuse cases to concrete design controls.
4. Establish review questions that every implementation RFC must answer.
5. Keep the proof/trust/test matrix honest about what is proven, tested,
   assumed, and out of scope.

---

## 3. Non-goals

1. This RFC does not claim cryptographic secrecy is proven by kroopt.
2. This RFC does not evaluate HACL*/EverCrypt primitive correctness.
3. This RFC does not define a full operational incident-response policy for a
   deployment organization.
4. This RFC does not cover client role, mTLS, tickets, HRR, KeyUpdate, or TLS
   1.2 except as future threat-model extensions.

---

## 4. Trust boundaries

```text
Remote peer / network
  └─ attacker-controlled bytes, timing, close behavior
     ↓
Kroopt parser and verified core
  └─ only structured events and bounded records may pass
     ↓
Kroopt interpreter
  ├─ iotakt transport calls       (assumed upstream correctness)
  └─ HACL*/EverCrypt FFI calls    (tested shim; primitives assumed verified)
     ↓
jemmet plaintext API
  └─ receives only authenticated plaintext after connected
```

Boundary rules:

1. Network input is hostile until parsed, size-checked, state-checked, and, for
   encrypted records, authenticated.
2. Secret material is never part of logging, public errors, `Repr`, or serialized
   state.
3. FFI results are correlated to a pending operation id before being accepted by
   the verified core.
4. iotakt readiness is a hint, not a guarantee.
5. jemmet must not observe TLS plaintext before the `connected` phase.

---

## 5. Assets

| Asset | Security property | Owner | Main controls |
|---|---|---|---|
| Application plaintext | Confidentiality, authenticity before emission | kroopt until delivered to jemmet | AEAD open gate, no-early/no-unauth proofs |
| Private key | Non-disclosure, correct use only | crypto provider / secret arena | `SecretKeyHandle`, non-printable types, config lint |
| Traffic secrets | Non-disclosure, key separation | crypto provider / kroopt handles | epochs, direction tags, zeroization |
| Nonces | Uniqueness per AEAD key | verified core | sequence monotonicity proof, overflow fatal |
| Transcript | Exact ordered wire-byte binding | verified core | transcript event model, hash update discipline |
| Connection state | Legal transitions | verified core | `step` proofs, no interpreter protocol branching |
| Pending queues | Bounded memory use | interpreter | byte budgets, queue caps, backpressure |
| Logs and metrics | Diagnostic value without leakage | kroopt/jemmet integration | redaction, structured event taxonomy |
| Configuration | Correct cert/key/SNI/ALPN policy | operator through jemmet/kroopt config | immutable validated config snapshots |

---

## 6. Attacker capabilities

The remote attacker may:

1. send arbitrary bytes at any time;
2. fragment TLS records across many transport reads;
3. coalesce multiple records into a single read;
4. send oversized records or handshake vectors;
5. send duplicate, unknown, malformed, or inconsistent extensions;
6. omit required TLS 1.3 fields such as acceptable X25519 key_share;
7. attempt downgrade or version-confusion behavior;
8. send records in illegal states;
9. send bad AEAD tags or bad Finished data;
10. close abruptly, half-close, or delay indefinitely;
11. trigger repeated would-block/progress paths;
12. attempt log injection through SNI or extension data;
13. open many connections to exhaust memory or CPU.

The remote attacker cannot:

1. directly call Lean APIs except through bytes over transport;
2. read process memory except through vulnerabilities;
3. forge HACL*/EverCrypt primitive correctness failures;
4. bypass iotakt's fd generation protection except through upstream bugs.

---

## 7. Local misuse model

A trusted local caller may accidentally:

1. call `send` before handshake completion;
2. forget to call `flush`/`progress`;
3. reuse stale connection handles;
4. configure overlapping SNI patterns;
5. configure a certificate and key that do not match;
6. log public errors with attacker-controlled details;
7. set unsafe resource limits.

kroopt mitigates these through typed results, configuration validation,
capability-limited APIs, explicit flush semantics, and safe error types.

---

## 8. Abuse-case matrix

| Abuse case | Expected kroopt behavior | RFC control |
|---|---|---|
| Oversized ClientHello | Reject with deterministic error/alert; no unbounded allocation | RFC 003, 019 |
| Duplicate supported_versions | Reject before state transition | RFC 003, 006 |
| Missing X25519 key_share | Fail cleanly; no HRR in current scope | RFC 006 |
| Bad AEAD tag | Fatal alert; emit no plaintext | RFC 004, 013 |
| Sequence number overflow | Fatal before nonce reuse | RFC 005 |
| Crypto result replay | Reject by operation id and phase | RFC 008, 010 |
| Write after close | `closed`/error result; no transport write except already selected alert | RFC 013 |
| Slowloris handshake | Timeout and byte budget termination | RFC 019 |
| Log injection through SNI | Redacted/escaped structured log field | RFC 020 |
| FFI pointer misuse | No retained Lean pointers; sanitizer tests | RFC 009 |
| Config overlap | Config validation failure or deterministic priority | RFC 011, 021 |

---

## 9. Security-review checklist

Every implementation RFC must answer:

1. What attacker-controlled inputs does this RFC parse or store?
2. What resource budget does it consume?
3. What state transitions does it permit?
4. Does it create, read, write, copy, or log secret material?
5. Does it call FFI or interpret FFI results?
6. Does it affect transcript bytes, keys, nonces, or sequence numbers?
7. What are the deterministic failure modes?
8. What is proven, what is tested, and what is assumed?
9. What fuzz or negative tests are required?
10. What would a dependent such as jemmet be allowed to rely on?

---

## 10. Acceptance criteria

1. `docs/src/threat-model.md` exists and mirrors this RFC.
2. Each RFC contains a threat/security section answering the checklist above.
3. Abuse cases are represented in deterministic tests or fuzz targets where
   executable.
4. The proof/trust/test matrix includes threat-model assumptions explicitly.
5. Before v0.3, all network-exposed hostile-input cases in this RFC have either a
   test, a proof, or an explicit documented assumption.
