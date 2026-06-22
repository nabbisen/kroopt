import Kroopt.Crypto.NativeSecret

/-!
Tests for the C-owned zeroizing secret arena (RFC 037 §3). The decisive check is that
`zeroize` actually overwrites the live buffer — observable while the slot is still allocated —
so the wipe is real, not asserted. The rest pin the lifecycle: round-trip, release-removes-slot,
safe double release, never-reused ids (no ABA / use-after-free of a recycled id), and no leak.
-/

namespace Tests.NativeSecret

open Kroopt.Crypto.NativeSecret

def bytesEq (a b : ByteArray) : Bool := a.toList == b.toList
def rep (n : Nat) (v : UInt8) : ByteArray := ByteArray.mk (Array.mkArray n v)

def main : IO UInt32 := do
  let base ← liveCount
  let secret := ByteArray.mk #[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]

  -- (1) round-trip through C-owned memory
  let id ← alloc secret
  let r1 ← read id
  let roundTrip := id != 0 && bytesEq r1 secret

  -- (2) zeroize overwrites the live buffer with zeros — the wipe is observable, not just claimed
  zeroize id
  let r2 ← read id
  let wiped := r2.size == secret.size && bytesEq r2 (rep secret.size 0) && ! bytesEq r2 secret

  -- (3) release removes the slot entirely
  release id
  let r3 ← read id
  let releasedGone := r3.size == 0

  -- (4) double release is a safe no-op
  release id
  let r4 ← read id
  let doubleReleaseSafe := r4.size == 0

  -- (5) a freed id is never reused; a new alloc gets a fresh id with its own bytes
  let s2 := rep 32 0x5A
  let id2 ← alloc s2
  let freshId := id2 != id && id2 != 0
  let r5 ← read id2
  let oldStillGone := (← read id).size == 0
  let newReads := bytesEq r5 s2 && oldStillGone

  -- (6) live-count tracks alloc/release with no leak
  let afterAlloc ← liveCount
  release id2
  let afterRelease ← liveCount
  let leakClean := afterAlloc == base + 1 && afterRelease == base

  let checks : List (String × Bool) :=
    [ ("alloc + read round-trips the secret bytes through C-owned memory", roundTrip)
    , ("zeroize overwrites the live buffer with zeros (the wipe is real)", wiped)
    , ("release removes the slot (read returns empty)", releasedGone)
    , ("double release is a safe no-op", doubleReleaseSafe)
    , ("a freed id is never reused — a new alloc gets a fresh id (no ABA)", freshId)
    , ("a fresh handle reads its own bytes; the released one stays gone", newReads)
    , ("live-count tracks alloc/release with no leak", leakClean) ]

  let mut passed := 0
  for (name, ok) in checks do
    IO.println s!"  {if ok then "PASS" else "FAIL"}  {name}"
    if ok then passed := passed + 1
  if passed == checks.length then
    IO.println s!"All {checks.length} checks passed."
    return 0
  else
    IO.println s!"{checks.length - passed} of {checks.length} checks FAILED."
    return 1

end Tests.NativeSecret

def main : IO UInt32 := Tests.NativeSecret.main
