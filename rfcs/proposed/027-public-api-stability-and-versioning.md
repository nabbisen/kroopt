# RFC 027 — Public API Stability and Versioning

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M0; commitment v0.3/v0.4  
**Depends on.** RFC 001, RFC 010, RFC 011, RFC 012, RFC 020  
**Touches.** public module boundary; `docs/src/public-api.md`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's public API stability policy. kroopt's first consumers
are jemmet and possibly other iotakt-based protocol libraries. The API must be
stable enough for dependents, but early proof-driven design must retain freedom
to correct unsafe or awkward interfaces.

---

## 2. API zones

| Zone | Examples | Stability |
|---|---|---|
| Public dependent API | `TlsConn`, config builders, result types, ALPN query | semver-governed after stabilization |
| Public diagnostics | error categories, security events | stable categories, expandable variants |
| Experimental API | advanced config reload, test hooks | explicitly unstable |
| Internal API | core state constructors, parser internals | no stability promise |
| Native shim API | C functions behind Lean wrapper | private to kroopt |

---

## 3. Public API principles

1. Prefer opaque types with safe constructors.
2. Do not expose secret handles except where needed as opaque references.
3. Do not expose protocol state in a way that callers can forge.
4. Make `wouldBlock` and `wrote n` semantics unambiguous.
5. Return typed errors, not strings.
6. Allow addition of new cipher suites/ALPN policies without breaking callers.
7. Keep jemmet's abstraction uniform across plaintext iotakt and kroopt TLS.

---

## 4. Versioning policy

Before public stabilization:

- breaking changes allowed with changelog entries;
- RFC updates required for public API shape changes;
- jemmet integration tests updated in lockstep.

After stabilization:

- breaking public API changes require major/minor version policy as adopted by
  the surrounding Lean ecosystem;
- security fixes may tighten validation and reject previously accepted invalid
  input without being considered a compatibility break;
- adding new error variants requires default handling guidance.

---

## 5. Deprecation policy

Deprecated APIs must include:

1. replacement API;
2. security reason if applicable;
3. planned removal milestone;
4. migration note for jemmet.

No deprecated API may bypass the verified core or weaken security guarantees.

---

## 6. Documentation requirements

Public API docs must include:

- example TLS listener setup;
- example `TlsConn` progress loop;
- write/flush semantics;
- ALPN query timing;
- close behavior;
- error classification and redaction;
- explicit non-goals.

---

## 7. Acceptance criteria

1. Public/internal module boundary is documented.
2. `TlsConn` and config APIs have examples before jemmet integration.
3. Error and event categories have stability notes.
4. Breaking API changes after v0.3 require RFC or changelog entry.
5. Native shim functions are not treated as public API.
