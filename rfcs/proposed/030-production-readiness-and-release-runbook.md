# RFC 030 — Production Readiness and Release Runbook

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.4 and every release after  
**Depends on.** RFC 020, RFC 022, RFC 026, RFC 028, RFC 029  
**Touches.** `docs/src/release-runbook.md`; release CI gates  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the release-readiness checklist for kroopt. A TLS layer can pass
unit tests yet still be unready for edge deployment if documentation, interop,
security review, proof inventory, fuzzing, and operational diagnostics are stale.
This runbook prevents that.

---

## 2. Release readiness checklist

A release candidate must have:

1. clean Lean build;
2. proof hygiene gate passing;
3. theorem inventory current;
4. proof/trust/test matrix current;
5. deterministic model tests passing;
6. parser and negative tests passing;
7. fuzz smoke tests passing;
8. native KATs passing if crypto provider is included;
9. sanitizer jobs passing for native shim;
10. OpenSSL/curl interop passing for network-enabled releases;
11. jemmet+iotakt E2E passing for integration releases;
12. documentation updated;
13. known limitations listed;
14. no release blockers from RFC 028.

---

## 3. Version-specific readiness

### 3.1 Core-only release

Requires proof/model/test readiness. Must clearly state that it is not a usable
TLS terminator.

### 3.2 Crypto-provider release

Requires KATs, sanitizer-clean shim, and secret-handle review.

### 3.3 Network interop release

Requires hostile-input negative matrix and resource-budget tests.

### 3.4 jemmet-facing release

Requires public API docs, progress-loop examples, ALPN/SNI docs, and E2E tests.

---

## 4. Release notes structure

Each release note includes:

- milestone and scope;
- public API changes;
- security-relevant changes;
- proof status changes;
- interop matrix changes;
- known limitations;
- upgrade notes for jemmet/iotakt consumers.

---

## 5. Rollback considerations

Because kroopt is used at the edge, releases should be easy to disable or roll
back in jemmet deployment. The runbook should document:

1. how to switch a listener back to plaintext for local testing only;
2. how to revert to previous kroopt config snapshot;
3. how to identify handshake failure spikes;
4. how to collect redacted diagnostics.

This RFC does not recommend deploying plaintext publicly; rollback guidance is
for operational control and local staging.

---

## 6. Acceptance criteria

1. `docs/src/release-runbook.md` exists before v0.4.
2. Release checklist is executed for every archive/tag.
3. Release notes include proof/test/assumption deltas.
4. Security blockers have explicit signoff.
5. The release never claims cryptographic properties beyond the established
   trust boundary.
