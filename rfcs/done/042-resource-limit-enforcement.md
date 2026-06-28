# RFC 042 — Resource-limit enforcement and configurability

**Status.** Implemented (0.115–0.116.0-dev). The substantive A1 + B1 + C2 implementation landed in
0.115.0-dev and was **accepted by implementation review** as correct in substance. The review's
non-blocking cleanup items — three stale doc/comment sites and a `TlsConn.send` terminal-state precedence
wart — were closed out in 0.116.0-dev.
**Tracks.** Making the per-connection outbound-ciphertext queue self-bounded (RFC 019, external design
§5.5), making the resource limits part of validated configuration, and removing budget code that was
proved but never called.
**Touches.** `Kroopt/Core/Config.lean` (`ResourceLimits` + `limits` threading + `validLimits`),
`Kroopt/Core/Budget.lean` (dead functions removed), `Kroopt/Core/State.lean` (`BudgetState` trimmed),
`Kroopt/Core/Handshake.lean`, `Kroopt/Core/RecordPath.lean` (charge sites use validated config),
`Kroopt/Conn/TlsConn.lean` (egress backstop in `send`; fuel from config), `Kroopt/Error.lean`
(`ConfigError.invalidLimits`), `Kroopt/Proofs/*` (allocOp helpers rethreaded; dead proofs removed),
`Tests/Conn.lean`, `Tests/Config.lean`, `Tests/Hardening.lean`, `scripts/check-hygiene.sh`, and the
budget / theorem-inventory / jemmet-integration docs.

## Problem

The 0.114 review of jemmet RFC 009 surfaced that `maxPendingCiphertextBytes` could be neither pinned
globally nor derived per-listener, because there was no configuration path to it at all and the charge
function (`chargePendingCiphertext`) had zero callers — the only thing bounding kroopt's outbound queue
was the consumer's own accounting. The same probe found a wider specified-but-dead budget surface:
`chargeExtensions`, `chargeProgressStep`, and `checkRecordSize` were defined and *proved* but never called,
and every wired charge site hardcoded `ResourceLimits.standard`. Proving lemmas over code that never runs
is, for a verification-first project, a contained instance of the proof/runtime drift the architecture
exists to prevent.

## Decision (A1 + B1 + C2)

### A1 — interpreter egress backstop (hard post-accept cap)

The outbound-ciphertext queue lives in the interpreter (`rt.outbound`), not in `Core.step`. Refusing more
plaintext when that queue is full is buffer/back-pressure management, not a protocol decision, so the cap
lives in `TlsConn.send` and the `Core.step` proofs are untouched.

`send` enforces a **hard post-accept invariant**, not a mere pre-check: after any successful send,
`rt.outbound.size ≤ maxPendingCiphertextBytes`. Algorithm — `remaining = cap - rt.outbound.size`; if
`remaining < minProtectedRecordLen` (23, the sealed length of a one-plaintext-byte record) it returns
`wouldBlock` with zero consumed; otherwise it admits the largest prefix whose sealed record fits,
`n = min (min plaintext.size maxPlaintextFragment) (remaining - 22)`, where a sealed application record is
deterministically `n + 22` bytes (5 header + n + 1 inner content-type + 16 AEAD tag, no padding). The send
contract is preserved: `wouldBlock` ⇒ zero consumed; `wrote n` ⇒ exactly n plaintext accepted and queued.

**Fatal alerts bypass the cap.** A fatal alert is a terminal-control record, bounded to one record with
terminalization preventing further growth; it is queued best-effort even when the app cap is full. The cap
gate lives only on the application-data send path, so alert framing is unaffected by design.

A2 (in-core egress accounting) was rejected for now: the core emits writes fire-and-forget and would need a
new drain-credit event and an expanded RFC 031 correspondence surface. If a core-visible outbound model is
ever wanted it is deferred to RFC 040. A3 (consumer-only) was rejected because kroopt already owns
`rt.outbound`, so a local cap is cheap defense-in-depth and keeps jemmet's RFC 009 assumptions true.

### B1 — thread validated `ResourceLimits` through configuration

`ServerConfig` gains `limits : ResourceLimits := .standard`; `ValidatedServerConfig` carries the validated
`limits`; the connection reads them via `State.serverConfig.limits`. Charge sites
(`chargeHandshakeBytes`, `chargeClientHelloBytes`, `allocOp`'s crypto-op budget) and the `driveEvents`
progress fuel now read the connection's configured limits instead of the `.standard` literal. `ResourceLimits`
lives in `Config.lean` (upstream of `State`/`Budget`) so the validated config can carry it without an import
cycle. Limits are **not** endpoint-specific: several apply before SNI selection, and the outbound queue is
connection-owned. `validateServerConfig` rejects bad limits with `ConfigError.invalidLimits` —
`maxHandshakeBytes > 0`, `maxClientHelloBytes > 0`, `maxClientHelloBytes ≤ maxHandshakeBytes`,
`maxPendingCryptoOps > 0`, `maxPendingCiphertextBytes ≥ minProtectedRecordLen`, `maxProgressStepsPerCall > 0`.

A Lean footgun fixed in passing: a `deriving Inhabited` structure gives `Nat` fields `0`, not their field
defaults, so a config defaulting its limits through `Inhabited` would have rejected every ClientHello. An
explicit `instance : Inhabited ResourceLimits := ⟨{}⟩` makes the default equal the standard ceilings.

### C2 — remove dead budget code; document the running mechanism

Removed: `chargeExtensions`, `chargeProgressStep`, `checkRecordSize`, `chargePendingCiphertext` and their
proofs (`chargeExtensions_bounded`, `chargeProgressStep_bounded`, `checkRecordSize_rejects_over`); the
`ResourceLimits` fields `maxExtensions` and `maxRecordPlaintextBytes`; and the `BudgetState` fields
`extensionsSeen`, `pendingCiphertextBytes`, `pendingPlaintextRecords`, `pendingCryptoOps`,
`progressStepsThisCall`. `ResourceLimits` is now exactly the five enforced ceilings; `BudgetState` is the two
charged byte counters. The handshake-byte budget keeps its three proofs (`_bounded`, `_rejects_over`,
`_accounts`). The other ceilings are enforced by their running mechanism and tested/documented there:
record size by the parser (`Reader.lengthExceedsMax`), extension count transitively by `maxClientHelloBytes`,
progress steps by `driveEvents` fuel, and outbound ciphertext by the A1 backstop (`Tests/Conn`). A hygiene
gate (`check-hygiene.sh`) now fails if `ResourceLimits.standard` is named at a charge site rather than read
from validated config (only `Config.lean` may name it).

## Tests

Egress (`Tests/Conn`): `sendAtCiphertextCapWouldBlockZeroConsumed`,
`sendBelowCiphertextCapAcceptsAndStaysWithinCap`, `sendNearCapAcceptsOnlyFittingPrefixOrWouldBlock`
(validates the exact `n + 22` prefix fit), `flushReducesOwnedOutboundBytesThenSendCanProceed`,
`ownedOutboundBytesNeverExceedsConfiguredLimit`, `alertRecordsRespectOutboundCapOrAreBestEffortDocumented`
(fatal-alert bypass). Config (`Tests/Config`): `serverConfigCarriesResourceLimits`,
`validatedConfigRejectsImpossibleCiphertextLimit`, a zero-limit rejection, and
`custom{PendingCryptoOps,HandshakeByte,ClientHello,Ciphertext}LimitIsUsed`. Honesty: the hygiene gate above;
the theorem inventory carries no dead-function rows; the budget docs name each limit's running mechanism.

## Threat-model note

The egress backstop is defense-in-depth on an interpreter-owned buffer; it adds no new external integration
and changes no safety proof. The audited theorem set drops from 109 to 106 by deleting proofs over removed
dead code — a reduction in *claimed* surface, not in enforced behavior.

## jemmet

Contract correction sent at decision time: before this remediation kroopt exposed `ownedOutboundBytes` but
did not self-bound it; after, kroopt self-bounds per-connection outbound ciphertext per the validated
listener `ResourceLimits`, while jemmet retains aggregate/global admission and egress budgeting.
