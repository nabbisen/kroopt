# RFC 029 — Developer Documentation and Examples

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.3; v0.4  
**Depends on.** RFC 010, RFC 011, RFC 012, RFC 020, RFC 027  
**Touches.** `docs/src/` developer guides; `examples/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the documentation and examples needed for jemmet and future
iotakt consumers to use kroopt safely. Because kroopt exposes security-sensitive
semantics such as `send` consumption, flush/progress, ALPN handoff, and terminal
states, examples must teach the correct loop rather than only list APIs.

---

## 2. Documentation set

Required docs:

1. `README.md` — purpose, non-goals, quick start, trust boundary;
2. `docs/src/boundary.md` — iotakt/kroopt/jemmet responsibilities;
3. `docs/src/public-api.md` — public modules and stable types;
4. `docs/src/tlsconn-loop.md` — correct progress loop;
5. `docs/src/configuration.md` — SNI/ALPN/cert/resource config;
6. `docs/src/errors-and-alerts.md` — public error semantics;
7. `docs/src/security-model.md` — threat model summary and non-claims;
8. `docs/src/interop.md` — tested clients and limitations;
9. `docs/src/proof-trust-test-matrix.md` — proof/test/assumption status.

---

## 3. Example programs

Minimum examples:

1. fake transport synthetic handshake;
2. real iotakt TLS echo server;
3. jemmet HTTPS listener wiring;
4. SNI with two certificate entries;
5. ALPN negotiation for `http/1.1`;
6. graceful close handling;
7. handling `wouldBlock` and `flush` correctly;
8. logging redacted security events.

---

## 4. Example safety rules

Examples must not:

1. ignore `flush`;
2. assume `wrote n` means peer received data;
3. log plaintext or raw TLS bytes;
4. use production-looking private keys without warnings;
5. enable deferred features such as tickets, HRR, or TLS 1.2;
6. bypass config validation.

---

## 5. API doc style

Every public operation should document:

- when it is legal;
- what it consumes or owns;
- what it may return;
- terminal-state behavior;
- security notes;
- relation to iotakt readiness;
- relation to core proof claims if relevant.

---

## 6. Acceptance criteria

1. Public API docs exist before jemmet integration is accepted.
2. At least one full correct progress-loop example exists.
3. Examples are tested or compile-checked where practical.
4. Documentation clearly says server mode presents certificates but does not
   validate peer chains.
5. Documentation uses the fixed requirements as the sole developer-facing
   baseline and does not depend on historical comparison language.
