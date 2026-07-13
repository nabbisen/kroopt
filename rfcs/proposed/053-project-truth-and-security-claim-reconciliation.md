# RFC 053 — Project Truth and Security-Claim Reconciliation

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking documentation/governance fix  
**Target milestone.** AR0  
**Requires completion of.** [Tracked architecture-review baseline for 0.124.1](../../docs/src/verification/architecture-review-0.124.1.md), [RFC 018](../done/018-data-classification-and-lifecycle.md), [RFC 020](../done/020-observability-audit-logging-and-redaction.md), [RFC 030](../done/030-production-readiness-and-release-runbook.md)  
**Coordinates with.** [RFC 027](027-public-api-stability-and-versioning.md), [RFC 040](040-native-traffic-secret-arena.md), and the [AR remediation RFC set](../README.md#proposed--architecture-review-remediation-schedule)  
**Touches.** README, security/current-state docs, roadmap, RFC index, releases, changelog and handoffs  

## Review finding

Architecture review found that public/handoff readiness and secret-residency claims exceed the implementation,
while several purported current-status documents describe older milestones. Release publishing text, proposed
RFC pending rows, and a duplicated changelog section also drift from repository state.

## Decision

The project presents itself as a proof-backed **pre-production TLS implementation** until AR0–AR3 pass.
Traffic-secret zeroization is described as best-effort logical invalidation until
[RFC 040](040-native-traffic-secret-arena.md) passes; config
private-key native residency remains a separate tested claim. Historical milestone prose is labeled historical
or archived and cannot compete with one version-current security/status page.

## Work breakdown

1. Make a version-current security/status page the documented current-state authority.
2. Correct README crypto breadth, interop, secret residency, production readiness, and stable support wording.
3. Correct `RELEASES.md` to reflect actual published tags and candidate-specific evidence.
4. Reconcile `rfcs/README.md` pending rows/status prose with current files and the AR schedule.
5. Remove the duplicated `0.123.1` changelog section without rewriting historical facts.
6. Mark stale roadmap/doc sections as historical or move them into an archive/generated history.
7. Update handoff templates so claims require `Done/Pending/N/A` plus candidate-specific evidence.

## Acceptance criteria

1. README, SECURITY, current-security-state, trust matrix, RFC index, releases, roadmap, and latest handoff
   make compatible claims for the same revision.
2. No document states traffic secrets are C-owned/zeroized before
   [RFC 040](040-native-traffic-secret-arena.md) completion.
3. No document reports a green canonical gate without a matching retained ledger.
4. Proposed/done/archive folder state matches every RFC status and index link.
5. Documentation link/build/hygiene checks pass in the canonical gate.
6. A reviewer can identify current capability, blockers, supported status, and next milestone from one page.

## Non-goals

This RFC does not resolve the underlying protocol or secret-residency blockers; it makes their status truthful
while the [AR remediation RFC set](../README.md#proposed--architecture-review-remediation-schedule) and
[RFC 040](040-native-traffic-secret-arena.md) resolve them.
