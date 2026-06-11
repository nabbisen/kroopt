/-!
# Kroopt.Core.Id

Non-secret identity and correlation tokens (RFC 002 §3, RFC 005 §3).

These ids correlate transport events, crypto operations, and connection
generations. They are not secret and are safe to log; they carry generation
counters so stale events/results can be rejected at the boundary (RFC 002 §5,
RFC 010 §8).
-/

namespace Kroopt.Core

/-- Stable connection identity: a value paired with a monotone generation. A
stale transport event or crypto result for an old generation is rejected before
it reaches `step` (RFC 002 §5). -/
structure ConnId where
  value : UInt64
  generation : UInt64
  deriving DecidableEq, Repr, Inhabited

/-- Identifies one outstanding crypto operation so a returning `cryptoResult`
can be correlated to the `callCrypto` that requested it. Unmatched ids are
stale and rejected (RFC 008 §5). -/
structure OperationId where
  value : UInt64
  deriving DecidableEq, BEq, Repr, Inhabited, Ord

/-- Immutable configuration snapshot identity. A connection keeps the generation
it was created with for its whole lifetime; reloads create a new generation and
never mutate live connections (RFC 011 §6, RFC 021 §7). -/
structure ConfigGeneration where
  value : UInt64
  deriving DecidableEq, Repr, Inhabited

end Kroopt.Core
