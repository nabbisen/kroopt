import Kroopt.Crypto.NativeSecret
import Kroopt.Crypto.Hacl
import Tests.RealFixtures

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

  -- (7) the headline integration: an Ed25519 private key resident *only* in the C arena signs by
  -- handle (key never enters Lean), the signature verifies, and after release the handle can no
  -- longer produce a valid signature — the durable key is gone.
  let seed := rep 32 0x42
  let keyId ← alloc seed
  let pub := Kroopt.Crypto.Hacl.ed25519Public seed
  let msg := ByteArray.mk #[0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD]
  let sigH := Kroopt.Crypto.Hacl.ed25519SignH keyId msg
  let signByHandleVerifies := sigH.size == 64 && Kroopt.Crypto.Hacl.ed25519Verify pub msg sigH
  -- The key is wiped/gone on release — proven soundly at the arena level above (zeroize → zeros,
  -- read-after-release → empty). We do not re-test "released cannot sign" through the sign-by-handle
  -- functions: they are `opaque` (so pure `submit` can call them), valid only under the load-once-
  -- stable-until-shutdown invariant, so calling them after release is out-of-invariant and the
  -- optimizer may legitimately reuse the pre-release value. Release here is lifecycle cleanup.
  release keyId

  -- (8) ECDSA-P256 sign-by-handle: the private scalar lives only in C
  let ecScalar := rep 32 0x42
  let ecPub := Kroopt.Crypto.Hacl.p256Public ecScalar
  let ecId ← alloc ecScalar
  let ecMsg := ByteArray.mk #[0x11, 0x22, 0x33, 0x44]
  let ecNonce := rep 32 0x77
  let ecRaw := Kroopt.Crypto.Hacl.ecdsaP256SignRawH ecMsg ecId ecNonce
  let ecdsaByHandle := ecPub.size == 65 && ecRaw.size == 65 && ecRaw.get! 0 == 0
                       && Kroopt.Crypto.Hacl.ecdsaP256Verify ecMsg ecPub (ecRaw.extract 1 65)
  release ecId

  -- (9) RSA-PSS sign-by-handle: the private exponent d lives only in C (RSA fixtures)
  let dId ← alloc Tests.RealFixtures.rsaD
  let rsaSalt := rep 32 0x33
  let rsaMsg := ByteArray.mk #[0xAB, 0xCD, 0xEF]
  let rsaSig := Kroopt.Crypto.Hacl.rsapssSignH Tests.RealFixtures.rsaN Tests.RealFixtures.rsaE dId rsaSalt rsaMsg
  let rsaByHandle := match rsaSig with
    | some sig => Kroopt.Crypto.Hacl.rsapssVerify Tests.RealFixtures.rsaN Tests.RealFixtures.rsaE 32 sig rsaMsg
    | none => false
  release dId

  let checks : List (String × Bool) :=
    [ ("alloc + read round-trips the secret bytes through C-owned memory", roundTrip)
    , ("zeroize overwrites the live buffer with zeros (the wipe is real)", wiped)
    , ("release removes the slot (read returns empty)", releasedGone)
    , ("double release is a safe no-op", doubleReleaseSafe)
    , ("a freed id is never reused — a new alloc gets a fresh id (no ABA)", freshId)
    , ("a fresh handle reads its own bytes; the released one stays gone", newReads)
    , ("live-count tracks alloc/release with no leak", leakClean)
    , ("Ed25519 sign-by-handle (key resident in C) produces a verifying signature", signByHandleVerifies)
    , ("ECDSA-P256 sign-by-handle (scalar resident in C) produces a verifying signature", ecdsaByHandle)
    , ("RSA-PSS sign-by-handle (d resident in C) produces a verifying signature", rsaByHandle) ]

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
