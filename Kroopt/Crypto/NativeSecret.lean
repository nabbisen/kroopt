/-!
# Kroopt.Crypto.NativeSecret

The IO-facing binding to the **C-owned zeroizing secret arena** (RFC 037 §3,
requirements §13). Secret bytes live in malloc'd C memory addressed by an opaque,
monotonic, never-reused `SecretId`; `release` overwrites the buffer (volatile store,
not dead-store-eliminated) before freeing it, and `zeroize` wipes it in place. The
Lean side holds only the id, never the bytes' durable home.

This is the native target the staged `Kroopt.Crypto.SecretArena` (a pure
`List (UInt64 × ByteArray)` for determinism and proof visibility) is migrating onto:
the pure arena stays the handle/bookkeeping authority for the deterministic test and
proof seam, while this module provides the real zeroizable storage required before any
production/stable claim. Wiring the production interpreter onto it is the follow-on step.

Trust posture: zeroization is **TESTED / best-effort / not zeroization-guaranteed** — the
wipe is observable on a live buffer (`Tests.NativeSecret`) and the arena is leak/UAF-checked
under ASan/UBSan/LSan (`scripts/sanitizer-check.sh`), but the C standard cannot promise that
no spilled copy survives elsewhere, and ephemeral bytes that transit Lean for a crypto op are
outside this store's guarantee.
-/

namespace Kroopt.Crypto.NativeSecret

/-- An opaque handle into the C-owned secret arena. `0` is the null handle (allocation
failure / absent). Names a C slot, never bytes. -/
abbrev SecretId := UInt64

/-- Copy `bytes` into a fresh C-owned zeroizable buffer; returns its id (`0` on OOM or a
full table). -/
@[extern "kroopt_ffi_secret_alloc"]
opaque alloc (bytes : ByteArray) : IO SecretId

/-- Read a copy of the buffer a handle names, or `ByteArray.empty` if absent (released or `0`). -/
@[extern "kroopt_ffi_secret_read"]
opaque read (id : SecretId) : IO ByteArray

/-- Overwrite the buffer contents in place, keeping the slot allocated. -/
@[extern "kroopt_ffi_secret_zeroize"]
opaque zeroize (id : SecretId) : IO Unit

/-- Wipe then free the buffer, clearing the slot. Idempotent: an absent id is a no-op, so a
double release is safe. -/
@[extern "kroopt_ffi_secret_release"]
opaque release (id : SecretId) : IO Unit

/-- Number of live (un-released) slots — for leak assertions. -/
@[extern "kroopt_ffi_secret_live_count"]
opaque liveCount : IO UInt64

end Kroopt.Crypto.NativeSecret
