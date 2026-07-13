# RFC 044 — Async Crypto Offload and Result Correlation

**Project.** kroopt  
**Status.** Proposed (deferred; do not implement before [RFC 040](040-native-traffic-secret-arena.md) and AR4)  
**Type.** Future architecture / scope-control RFC  
**Target milestone.** Post-stable, on demonstrated need  
**Requires completion of.** [RFC 040](040-native-traffic-secret-arena.md) (native traffic-secret arena), [RFC 031](../done/031-production-interpreter-correspondence.md) (synchronous correspondence)  
**Coordinates with.** [RFC 025](025-performance-and-memory-benchmark-policy.md) for activation evidence  
**Touches.** Future IO interpreter, provider completion queue, jemmet egress accounting  

## Summary

This RFC reserves the asynchronous sealing/open and crypto-offload design that
[RFC 040](040-native-traffic-secret-arena.md) explicitly excludes.
It prevents async behavior from entering the stable secret-residency migration as an undocumented contract
change. No implementation is authorized by this proposal alone.

## Activation trigger

Work starts only when measurements show synchronous crypto is a material bottleneck and after
[RFC 040](040-native-traffic-secret-arena.md)'s promotion gate passes.
[RFC 025](025-performance-and-memory-benchmark-policy.md) evidence must state the workload,
latency/throughput target, and why simpler
batching or scheduling changes are insufficient.

## Required design

- generation-protected operation ids that cannot alias after wrap/reuse;
- bounded in-flight operations and explicit backpressure;
- duplicate, stale-generation, after-terminal, after-timeout, and failure-after-close results cannot mutate
  protocol state; every completion payload is nevertheless finalized;
- no result can emit plaintext or mutate protocol state unless the core still authorizes it;
- accepted-but-not-yet-sealed plaintext ownership is exposed to jemmet and included in egress budgets;
- each operation has a one-shot ownership state (`pending`, `accepted`, or `disposed`); accepting a result
  transfers its native handle exactly once, while rejecting a stale/duplicate/late result disposes every
  newly returned native handle exactly once before discarding metadata;
- terminal cleanup atomically claims and releases every still-pending native handle exactly once, and a
  later completion observes `disposed` and disposes only resources newly carried by that completion;
- the pure interpreter remains the executable specification.

## Acceptance criteria

1. An accepted internal design defines the queue, ownership, cancellation, and cleanup state machines.
2. Differential tests compare public observations of synchronous and asynchronous interpreters.
3. Negative tests cover every stale-result case listed by
   [RFC 040](040-native-traffic-secret-arena.md) and use counted fake handles to prove no
   leak and no double disposal.
4. Resource limits bound queued plaintext, operations, ciphertext, and completion processing.
5. The trust matrix distinguishes proved core authorization from tested async lifting.
6. jemmet's egress contract is updated and tested before the async path becomes default.

## Non-goals

- No async implementation as part of AR0–AR4.
- No change to TLS protocol decisions, record ordering, nonce allocation, or transcript rules.
- No weakening of [RFC 040](040-native-traffic-secret-arena.md)'s stable secret-residency gate.
