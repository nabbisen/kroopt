# ORDER STATEMENTS — kroopt → iotakt team

**Companion to:** `handoff/HANDOFF-iotakt-consumer-review.md`
**Date:** 2026-06-13
**Subject:** Directives and acceptance criteria for the kroopt↔iotakt consumer-contract review.

Each order below is a single thing we ask the iotakt team to confirm or return. Each carries an
acceptance criterion (what "done" looks like). Answers may be "confirmed", "confirmed with the following
correction", or "violation — here is what would be required" (the last being the outcome we most need to
surface early). Please answer every order explicitly; a silent omission is the worst case for us.

## Scope

**In scope:** only the kroopt↔iotakt seam — the `Transport` typeclass, its instances, the
event/action↔iotakt mapping, `FdKey`, readiness, partial I/O, and close semantics.

**Out of scope:** kroopt's protocol core, key schedule, record layer, transcript, parsers, proofs, and
the HACL\*/EverCrypt crypto FFI. Do not review these; they are validated independently. If something in
scope forces a change to them, note it as a finding rather than reviewing them directly.

## Orders

**O1 — Confirm the capability set is sufficient and minimal.**
kroopt requires exactly: `recv`, `send`, `enableWrite`, `disableWrite`, `closeConnection`, a
generation-protected `FdKey`, and `readable`/`writable` readiness events (Handoff §3.1).
*Accept when:* you confirm iotakt provides each, and that kroopt needs nothing more.

**O2 — Confirm kroopt requires NO TLS-aware iotakt API.**
The governing invariant (Requirements §2.3): if kroopt needs a TLS-specific iotakt API, the boundary is
violated.
*Accept when:* you confirm every kroopt transport call is a generic byte-channel primitive, or you list
each place kroopt reaches for something TLS-specific.

**O3 — Confirm the control-ownership model.**
kroopt's interpreter is event-driven: iotakt owns the event loop and invokes kroopt per `IoEvent`;
kroopt runs a bounded progress loop to a stable boundary and yields. (Our `SocketReactor` stand-in
inverts this by owning the loop — that is the stand-in's only structural deviation.)
*Accept when:* you confirm the intended integration is "iotakt drives kroopt per readiness event," and
describe the exact entry points/callbacks kroopt's adapter registers.

**O4 — Confirm the pure-Transport / IO-reactor staging pattern.**
Because `Transport` is pure, the real adapter performs iotakt `recv`/`send` in `IO`, stages bytes into
the `Transport` state, runs the pure interpreter, then drains staged outbound via iotakt `send`
(Handoff §3.2).
*Accept when:* you confirm this composes with iotakt's I/O model and does not conflict with an
iotakt-side buffering/ownership protocol — or you specify the adapter shape iotakt expects instead.

**O5 — Confirm `FdKey` structural and semantic identity.**
kroopt's `FdKey { fd : UInt64, generation : UInt64 }` is assumed identical to iotakt's, including
generation-based staleness filtering that kroopt relies on iotakt to perform.
*Accept when:* you confirm field types and generation semantics match, or give the exact iotakt `FdKey`
definition kroopt must adopt.

**O6 — Confirm readiness-as-hint and the write re-arm cycle.**
kroopt assumes `recv`/`send` may report would-block after a readiness event, and that
`enableWrite` → `writable` correctly re-arms a stalled write.
*Accept when:* you confirm both, or specify the precise readiness guarantees iotakt makes.

**O7 — Confirm partial-write reporting.**
kroopt's `SendOutcome.sent n` expects iotakt to report a partial-accept byte count, after which kroopt
keeps the unsent suffix and arms write interest.
*Accept when:* you confirm iotakt's write result exposes the accepted count and that this strategy
matches iotakt's `WriteBuffer` pattern.

**O8 — Confirm close semantics and ordering.**
kroopt's graceful close flushes a sealed `close_notify`, then calls `closeConnection`; abortive/fatal
closes route through the same `closeConnection`. `closeConnection` is understood to also cancel the
owning Henret task.
*Accept when:* you confirm the ordering is valid, the Henret-cancel side effect is correct, and that
kroopt need not (and must not) touch the raw fd.

**O9 — Confirm EOF is distinguishable from transport error.**
kroopt treats peer-EOF-before-`close_notify` as truncation (a failure), separate from a transport error,
and needs iotakt to signal the two distinctly.
*Accept when:* you confirm iotakt exposes a distinct peer-closed/EOF signal.

**O10 — Confirm buffer-ownership boundary.**
kroopt owns inbound record reassembly, the outbound pending-ciphertext queue, and a one-record plaintext
buffer; iotakt owns fd lifecycle and readiness.
*Accept when:* you confirm there is no double-buffering or ownership conflict with iotakt's WriteBuffer.

**O11 — Return the binding spec for `IotaktTransport`.**
Given O1–O10, provide the concrete iotakt API signatures (module/type/function names and shapes) that
kroopt's `IotaktTransport` instance must call, sufficient for us to replace `SocketReactor` without
guesswork.
*Accept when:* we can implement the `Transport` instance directly against the names you provide.

**O12 — Flag anything kroopt assumes that iotakt does not actually offer.**
Any kroopt assumption not covered by O1–O11 that is wrong, or any iotakt constraint kroopt must honor
that we have not accounted for.
*Accept when:* you have listed every such item, or confirmed there are none.

## Deliverables we expect back

1. A point-by-point response to O1–O12 (confirmed / corrected / violation).
2. A single explicit verdict on the **zero-iotakt-changes** invariant: upheld, or the enumerated changes
   iotakt would need (which we treat as a redesign trigger on the kroopt side, not an iotakt change).
3. The `IotaktTransport` binding spec from O11.
4. Any iotakt-side constraints or idioms kroopt must adopt that we missed.

## Priority

O2 and O3 first (they can invalidate the architecture), then O11 (it unblocks the real binding), then
the remainder. O12 last, as a sweep.

## What happens next on our side

On a clean review we replace `SocketReactor` with `IotaktTransport` against your binding spec, re-run
`scripts/tls-interop.sh` and `scripts/https-e2e.sh` over the real iotakt path, and only then begin the
jemmet integration (RFC 015) — so jemmet is never layered on an unvalidated transport boundary.
